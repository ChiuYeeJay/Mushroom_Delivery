#include<iostream>
#include<fstream>
#include<string>
#include<chrono>
#include<boost/array.hpp>
#include<boost/asio.hpp>
#include<cryptopp/aes.h>
#include<cryptopp/rsa.h>
#include<cryptopp/osrng.h>
#include<cryptopp/filters.h>
#include<cryptopp/files.h>
#include<cryptopp/modes.h>
#define CMD_EXCHANGE string("E")
#define CMD_CLI_SEND string("CS")
#define CMD_SER_SEND string("SS")
#define CMD_SND_INFO string("SI")
#define ACK string("ACK")
#define PARSE_BLANK '\5'
#define MAX_FRAG 1048576
#define BAR_LENTH 50
using namespace boost;
using namespace std;
using namespace CryptoPP;
using boost::asio::ip::tcp;

//TODO deal with the problem of nthl(), htnl()
//TODO show byte rate
//TODO add "agree" progress
//TODO add available file list
//TODO add history ip list
//TODO add setting file (bar's len)
//TODO delete rcv file when error happened
//TODO show time consumption

asio::ip::address typein_ip_address(){
    string in;
    asio::ip::address addr;
    while(1){
        cout << "server's IP(v4): ";
        cin >> in;
        try{
            addr = asio::ip::address::from_string(in);
            return addr;
        }
        catch(const std::exception& e){
            cout << "Wrong Format! Input Again!" << endl;
            continue;
        }
    }
}

size_t get_file_size(ifstream &file){
    size_t end;
    file.seekg(0, ios::end);
    end = file.tellg();
    file.seekg(0, ios::beg);
    return end - file.tellg();
}

string byte_format(long long b){
    int round;
    double f = b;
    char num[10];
    const char* unit[3] = {"KB", "MB", "GB"};
    string ans;
    if(b <= 1024){
        ans = to_string(b) + " B";
    }
    else{
        for(round=0;round<3;round++){
            f /= 1024;
            if(f <= 1024) break;
        }
        sprintf(num, "%.2f", f);
        ans.append(num);
        ans.push_back(' ');
        ans.append(unit[round]);
    }
    return ans;
}

void show_progress_bar(const long long file_size, const long long cur_size){
    static chrono::steady_clock::time_point last_clk;
    static int last_size;
    static int last_str_len;
    string bar, byte_str, size_str, out;
    chrono::steady_clock::time_point now_clk = chrono::steady_clock::now();
    double progress_rate;
    double byte_rate;
    double time_diff;
    if(last_size == 0){
        last_size = cur_size;
        last_clk = now_clk;
        progress_rate = cur_size*1.0/file_size;
        byte_rate = 0;
    }
    else{
        time_diff = chrono::duration_cast<chrono::milliseconds>((now_clk-last_clk)).count()/1000.0;
        if(time_diff < 0.01 && file_size>cur_size) return;
        else{
            progress_rate = cur_size*1.0/file_size;
            byte_rate = 1.0*(cur_size-last_size)/time_diff;
            last_clk = now_clk;
            last_size = cur_size;
            while(last_str_len--) printf("\b");
        }
    }

    bar = "|";
    for(int i=0;i<BAR_LENTH;i++){
        if(i<progress_rate*BAR_LENTH) bar.push_back('#');
        else bar.push_back('-');
    }
    bar.push_back('|');
    byte_str = " " + byte_format(round(byte_rate)) + "/s";
    size_str = to_string(100*progress_rate);
    size_str = " " + size_str.substr(0, min(size_str.find('.')+2, size_str.size())) + "%";
    out = bar + size_str + byte_str;
    last_str_len = out.size();
    printf("%s", out.data());
}

void exception_exit(const char* from, tcp::socket& socket){
    socket.close();
    cout << "Error: " << from << endl;
    exit(1);
}

void exception_exit(string from, tcp::socket& socket){
    socket.close();
    cout << "Error: " << from << endl;
    exit(1);
}

int main(){
    //> Declarations
    //* about asio socket
    // cout << "$about asio socket" << endl;
    asio::io_service io_service;
    tcp::acceptor acceptor(io_service);
    tcp::socket socket(io_service);
    tcp::endpoint end_point;
    //* about UI
    // cout << "$about UI" << endl;
    string cw_ans;
    string sr_ans;
    bool is_server;
    bool is_sender;
    //* about cryption
    // cout << "$about cryption" << endl;
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    SecByteBlock aes_key;
    SecByteBlock aes_iv(AES::BLOCKSIZE);
    //* about file
    // cout << "$about file" << endl;
    unsigned long long file_size;
    string file_name;
    string crypt_name;
    

    //> Waiting to accept or typing IP and connecting to other
    //* get choice
    // cout << "$get choice" << endl;
    cout << "Connect to other or Wait to be connected? (c/w)" << endl;
    cw_ans = "";
    do{
        if(cw_ans != "") cout << "Invalid Choice! Input Again!" << endl;
        cout << ">> ";
        cin >> cw_ans;
    }while(cw_ans != "c" && cw_ans != "w");
    //* set socket
    // cout << "$set socket" << endl;
    try{
        if(cw_ans == "c"){
            cout << "connecting..." << endl;
            end_point = tcp::endpoint(typein_ip_address(), 50000);
            // end_point = tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 50000);
            socket.connect(end_point);
            cout << "success! You are client!" << endl;
            is_server = false;
        }
        else{
            cout << "waiting..." << endl;
            acceptor = tcp::acceptor(io_service, tcp::endpoint(tcp::v4(), 50000));
            acceptor.accept(socket);
            cout << "connected! You are server!" << endl;
            is_server = true;
        }
    }
    catch(const std::exception& e){
        cerr << e.what() << std::endl;
        exception_exit("Something wrong when connecting socket", socket);
    }

    //> Exchange AES key
    cout << "preparing cryption..." << endl;
    try{
        if(is_server){
            //* generate RSA
            // cout << "$generate RSA" << endl;
            AutoSeededRandomPool rng;
            InvertibleRSAFunction params;
            params.GenerateRandomWithKeySize(rng, 2048);
            privateKey = RSA::PrivateKey(params);
            publicKey = RSA::PublicKey(params);

            //* write cmd to transfer public key to client
            // cout << "$write cmd to transfer public key to client" << endl;
            boost::array<char, 1024> rcv_buf = boost::array<char, 1024>();
            socket.wait(socket.wait_write);
            socket.write_some(asio::buffer(CMD_EXCHANGE));
            socket.wait(socket.wait_read);
            socket.read_some(asio::buffer(rcv_buf));
            socket.wait(socket.wait_write);
            if(rcv_buf.data() != ACK) exception_exit("transfer cmd EXCHANGE to client reply other than ACK", socket);

            //* write public key code to client
            // cout << "$write public key code to client" << endl;
            string pk_str;
            StringSink strsink(pk_str);
            publicKey.Save(strsink.Ref());
            socket.write_some(asio::buffer(pk_str));
            socket.wait(socket.wait_read);
            
            //* receive encrypted AES key
            // cout << "$receive encrypted AES key" << endl;
            rcv_buf = boost::array<char, 1024>();
            socket.read_some(asio::buffer(rcv_buf));
            socket.wait(socket.wait_write);
            socket.write_some(asio::buffer(ACK));
            
            //* decrypt AES key
            // cout << "$decrypt AES key" << endl;
            string aes_key_cipher = "";
            RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
            for(int i=0;i<256;i++) aes_key_cipher.push_back(rcv_buf[i]);
            aes_key = SecByteBlock(0x00, AES::DEFAULT_KEYLENGTH);
            ArraySink arrsnk(aes_key, AES::DEFAULT_KEYLENGTH);
            StringSource ss(aes_key_cipher, true, new PK_DecryptorFilter(rng, decryptor, new Redirector(arrsnk)));

            //* receive encrypted AES iv
            // cout << "$receive encrypted AES iv" << endl;
            rcv_buf = boost::array<char, 1024>();
            socket.wait(socket.wait_read);
            socket.read_some(asio::buffer(rcv_buf));
            socket.wait(socket.wait_write);

            //* decrypt AES iv
            // cout << "$decrypt AES iv" << endl;
            string aes_iv_cipher = "";
            for(int i=0;i<256;i++) aes_iv_cipher.push_back(rcv_buf[i]);
            ArraySink arrsnk2(aes_iv, AES::BLOCKSIZE);
            StringSource ss2(aes_iv_cipher, true, new PK_DecryptorFilter(rng, decryptor, new Redirector(arrsnk2)));
        }
        else{
            //* generate AES
            // cout << "$generate AES" << endl;
            AutoSeededRandomPool rnd;
            aes_key = SecByteBlock(0x00, AES::DEFAULT_KEYLENGTH);
            rnd.GenerateBlock(aes_key, aes_key.size());
            rnd.GenerateBlock(aes_iv, aes_iv.size());


            //* receive server cmd to exchange keys
            // cout << "$receive server cmd to exchange keys" << endl;
            boost::array<char, 1024> rcv_buf = boost::array<char, 1024>();
            socket.wait(socket.wait_read);
            socket.read_some(asio::buffer(rcv_buf));
            socket.wait(socket.wait_write);
            if(rcv_buf.data() != CMD_EXCHANGE) exception_exit("get cmd other than cmd_exchange", socket);
            socket.write_some(asio::buffer(ACK));
            socket.wait(socket.wait_read);
            
            //* receive public key from server
            // cout << "$receive public key from server" << endl;
            string str_pbkey = "";
            rcv_buf = boost::array<char, 1024>();
            socket.read_some(asio::buffer(rcv_buf));
            socket.wait(socket.wait_write);
            for(int i=0;i<292;i++) str_pbkey.push_back(rcv_buf[i]);
            StringSource str_sor(str_pbkey, true);
            publicKey.Load(str_sor);

            //* encrypt aes key with public key and send it to server
            // cout << "$encrypt aes key with public key and send it to server" << endl;
            RSAES_OAEP_SHA_Encryptor encrypter(publicKey);
            string aes_key_cipher;
            ArraySource as(aes_key, aes_key.size(), true, new PK_EncryptorFilter(rnd, encrypter, new StringSink(aes_key_cipher)));
            socket.write_some(asio::buffer(aes_key_cipher));
            rcv_buf = boost::array<char, 1024>();
            socket.wait(socket.wait_read);
            socket.read_some(asio::buffer(rcv_buf));
            if(rcv_buf.data() != ACK) exception_exit("transfer aes key to server rcving other than ACK", socket);

            //* encrypt aes iv with public key and send it to server
            // cout << "$encrypt aes iv with public key" << endl;
            string aes_iv_cipher;
            ArraySource as2(aes_iv, aes_key.size(), true, new PK_EncryptorFilter(rnd, encrypter, new StringSink(aes_iv_cipher)));
            socket.wait(socket.wait_write);
            socket.write_some(asio::buffer(aes_iv_cipher));
        }

        //* after exchanging
        // cout << "$after exchanging" << endl;
        cout << "complete!" << endl;
    }
    catch(const std::exception& e){
        cout << "failed!" << endl;
        cerr << e.what() << endl;
        exception_exit("Something wrong when exchanging AES key", socket);
    }

    //> Decide the sender
    try{
        if(is_server){
            //* set sender
            // cout << "$set sender" << endl;
            cout << "Sending or Receiving file? (s/r)" << endl;
            sr_ans = "";
            while(1){
                if(sr_ans != "") cout << "Invalid Choice! Input Again!" << endl;
                cout << ">> ";
                cin >> sr_ans;
                if(sr_ans == "s"){
                    boost::array<char, 128> rcv_buf = boost::array<char, 128>();
                    socket.wait(socket.wait_write);
                    socket.write_some(asio::buffer(CMD_SER_SEND));
                    socket.wait(socket.wait_read);
                    socket.read_some(asio::buffer(rcv_buf));
                    socket.wait(socket.wait_write);
                    if(rcv_buf.data() != ACK) exception_exit("send cmd SERSEND to client reply other than ACK", socket);
                    is_sender = true;
                    break;
                }
                else if(sr_ans == "r"){
                    boost::array<char, 128> rcv_buf = boost::array<char, 128>();
                    socket.wait(socket.wait_write);
                    socket.write_some(asio::buffer(CMD_CLI_SEND));
                    socket.wait(socket.wait_read);
                    socket.read_some(asio::buffer(rcv_buf));
                    socket.wait(socket.wait_write);
                    if(rcv_buf.data() != ACK) exception_exit("send cmd CLISEND to client reply other than ACK", socket);
                    is_sender = false;
                    break;
                }
            }
        }
        else{
            boost::array<char, 128> rcv_buf = boost::array<char, 128>();
            cout << "Waiting server's choice..." << endl;
            socket.wait(socket.wait_read);
            socket.read_some(asio::buffer(rcv_buf));
            socket.wait(socket.wait_write);
            if(rcv_buf.data() == CMD_SER_SEND){
                socket.write_some(asio::buffer(ACK));
                is_sender = false;
            }
            else if(rcv_buf.data() == CMD_CLI_SEND){
                socket.write_some(asio::buffer(ACK));
                is_sender = true;
            }
            else{
                exception_exit("receive other than cmd WHOSEND", socket);
            }
        }
    }
    catch(const std::exception &e){
        cerr << e.what() << endl;
        exception_exit("Something wrong when deciding the sender", socket);
    }

    //> Sender selcting and encrypting file / Receiver waiting
    if(is_sender){
        //* get the file
        // cout << "$get the file" << endl;
        ofstream cipher_file;
        ifstream source_file;
        cout << "You are sender! Choose file to deliver!" << endl;
        do{
            cout << "Your file(name/path): ";
            cin >> file_name;
            source_file.open(file_name, ios::binary | ios::in);
            if(source_file.fail()) cout << "Invalid file name! Input again!" << endl;
        }while(source_file.fail());
        cout << "Get your file \"" << file_name << "\" successfully!" << endl;
        
        //* set AES encryption
        // cout << "$set AES encryption" << endl;
        CFB_Mode<AES>::Encryption cfbEncryption(aes_key, aes_key.size(), aes_iv);

        //* encrypting the file
        // cout << "$encrypting the file" << endl;
        crypt_name = "cipher_" + file_name + ".crpt";
        try{
            cipher_file.open(crypt_name, ios::binary | ios::out);
            file_size = get_file_size(source_file);
            FileSource(source_file, true, new StreamTransformationFilter(cfbEncryption, new FileSink(cipher_file)));
            source_file.close();
            cipher_file.close();
        }
        catch(std::exception const &e){
            cerr << e.what() << endl;
            exception_exit("something wrong when sender encrypt the file", socket);
        }
    }
    else{
        cout << "You are receiver! Waiting sender selecting and processing file..." << endl;
    }

    //> Preparing Delivery
    if(is_sender){
        //* send file name and cipher size
        // cout << "$send file name and cipher size" << endl;
        boost::array<char, 128> rcv_buf = boost::array<char, 128>();
        string file_info = file_name;
        file_info.push_back(' ');
        file_info.append(to_string(file_size));
        // cout << "#" << file_info << endl;
        try{
            socket.wait(socket.wait_write);
            socket.write_some(asio::buffer(CMD_SND_INFO));
            socket.wait(socket.wait_read);
            socket.read_some(asio::buffer(rcv_buf));
            socket.wait(socket.wait_write);
            if(rcv_buf.data() != ACK) exception_exit("sending cmd SND_NAME to rcver, replying other than ACK", socket);
            rcv_buf = boost::array<char, 128>();
            socket.write_some(asio::buffer(file_info));
            socket.wait(socket.wait_read);
            socket.read_some(asio::buffer(rcv_buf));
            if(rcv_buf.data() != ACK) exception_exit("sending file name to rcver, replying other than ACK", socket);
        }
        catch(const std::exception &e){
            cerr << e.what() << endl;
            exception_exit("something wrong when send file name to rcver", socket);
        }
    }
    else{
        //* receive file name and cipher size
        // cout << "$receive file name and cipher size" << endl;
        boost::array<char, 1024> rcv_buf = boost::array<char, 1024>();
        string file_info;
        try{
            socket.wait(socket.wait_read);
            socket.read_some(asio::buffer(rcv_buf));
            socket.wait(socket.wait_write);
            if(rcv_buf.data() != CMD_SND_INFO) exception_exit("receive other than cmd SND_NAME", socket);
            rcv_buf = boost::array<char, 1024>();
            socket.write_some(asio::buffer(ACK));
            socket.wait(socket.wait_read);
            socket.read_some(asio::buffer(rcv_buf));
            socket.wait(socket.wait_write);
            file_info = rcv_buf.data();
            file_name = file_info.substr(0, file_info.find(' '));
            file_size = stoll(file_info.substr(file_info.find(' ')+1, file_info.size()));
            crypt_name = "cipher_" + file_name + ".crpt";
            cout << "File \"" << file_name << "\"(" << byte_format(file_size) << ") is going to be delivered!" << endl;
            socket.write_some(asio::buffer(ACK));
        }
        catch(const std::exception &e){
            cerr << e.what() << endl;
            exception_exit("something wrong when receiving file name", socket);
        }
    }

    //> Delivery
    if(is_sender){
        //* send file
        // cout << "$send file" << endl;
        ifstream cipher_file;
        char str[MAX_FRAG];
        long long remain_size = file_size;
        boost::system::error_code err;
        try{
            cipher_file.open(crypt_name, ios::binary | ios::in);
            if(cipher_file.fail()) exception_exit("something wrong when reopen encrypted file", socket);
            do{
                memset(str, 0, (MAX_FRAG)*sizeof(char));
                if(remain_size < MAX_FRAG){
                    cipher_file.read(str, remain_size);
                    socket.wait(socket.wait_write);
                    size_t s = socket.write_some(asio::buffer(str, remain_size));
                    remain_size -= s;
                    // cout << "#s=" << s << endl;
                }
                else{
                    cipher_file.read(str, MAX_FRAG);
                    socket.wait(socket.wait_write);
                    size_t s = socket.write_some(asio::buffer(str, MAX_FRAG));
                    remain_size -= s;
                    // cout << "#s=" << s << endl;
                }
                show_progress_bar(file_size, file_size-remain_size);
            }while(cipher_file.good() && remain_size > 0);
            printf("\n");
        }
        catch(const std::exception &e){
            cerr << e.what() << endl;
            exception_exit("something wrong when sending file", socket);
        }

        //* after sending file
        // cout << "$after sending file" << endl;
        boost::array<char, 128> rcv_buf = boost::array<char, 128>();
        try{
            socket.wait(socket.wait_read);
            socket.read_some(asio::buffer(rcv_buf));
            if(rcv_buf.data() != ACK) exception_exit(string("sending complete, receiving other than ACK") + rcv_buf.data(), socket);
            socket.close();
        }
        catch(const std::exception &e){
            cerr << e.what() << endl;
            exception_exit("something wrong after sending", socket);
        }
    }
    else{
        //* receive file
        // cout << "$receive file" << endl;
        boost::system::error_code err;
        char str[MAX_FRAG];
        int cur_size = 0;
        try{
            ofstream cipher_file;
            ofstream recover_file;
            cipher_file.open(crypt_name, ios::binary | ios::out);
            err.clear();
            while(1){
                memset(str, 0, (MAX_FRAG)*sizeof(char));
                socket.wait(socket.wait_read);
                size_t s = socket.read_some(asio::buffer(str), err);
                for(int i=0;i<s && cur_size < file_size;i++){
                    cipher_file.write(str+i, 1);
                    cur_size++;
                }
                // cout << "#" << s << endl;
                show_progress_bar(file_size, cur_size);
                if(cur_size >= file_size) break;
            }
            printf("\n");
            socket.wait(socket.wait_write);
            socket.write_some(asio::buffer(ACK));
        }
        catch(const std::exception &e){
            cerr << e.what() << endl;
            cout << "something wrong when receiving file" << endl;
            if(socket.is_open()) socket.close();
            exit(1);
        }
        cout << "file delivered successully!" << endl;

        //* decrypt file
        // cout << "$decrypt file" << endl;
        cout << "decrypting..." << endl;
        try{
            ifstream cipher_file;
            ofstream recover_file;
            cipher_file.open(crypt_name, ios::binary | ios::in);
            recover_file.open(file_name, ios::binary | ios::out);
            AutoSeededRandomPool rnd;
            CFB_Mode<AES>::Decryption cfbDecryption(aes_key, aes_key.size(), aes_iv);
            FileSource(cipher_file, true, new StreamTransformationFilter(cfbDecryption, new FileSink(recover_file)));
            cipher_file.close();
            recover_file.close();
        }
        catch(const std::exception &e){
            cerr << e.what() << endl;
            cout << "something wrong when decrypting file and close files" << endl;
            exit(1);
        }
    }

    //> after delivery
    try{
        std::system(("rm " + crypt_name).data());
    }
    catch(const std::exception &e){
        cout << "something wrong when deleting encrypted file, but who cares?";
    }
    cout << "File delivery complete, thank you for using!" << endl;
}