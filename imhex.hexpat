#pragma array_limit 10241024102400
#pragma pattern_limit 10241024102400

struct DatabaseHeader {
    u8 signature[16]; 
    u16 version;    
    u32 spoli;
    u32 spols;
    u32 hash;
    u32 asn_count;   
    u32 ipv4_count;  
    u32 ipv6_count;  
};

struct ASNEntry {
    u32 hash;
    u32 asn;       
    char country[4];    
    char description[8]; 
};

struct IPv4Entry {
    u32 hash;
    u32 asn;  
    u32 start_ip;
    u32 end_ip;
};

struct IPv6Entry {
    u32 hash;
    u32 asn;
    u8 start_ip[16];  
    u8 end_ip[16];    
};

DatabaseHeader db_header @ (0);

ASNEntry asn_entries[db_header.asn_count] @ (1024);

IPv4Entry ipv4_entries[db_header.ipv4_count] @ (1024 + db_header.asn_count * sizeof(ASNEntry));

IPv6Entry ipv6_entries[db_header.ipv6_count] @ (1024 + db_header.asn_count * sizeof(ASNEntry) + db_header.ipv4_count * sizeof(IPv4Entry));