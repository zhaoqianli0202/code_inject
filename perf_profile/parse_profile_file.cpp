#include <bits/types/struct_timeval.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <unistd.h>
#include <vector>
#include <iomanip>
#include <json/json.h>
#include "perf_profile.h"

class parser {
private:
    struct header_format {
        char event_name[NAME_MAX_LEN];
        uint64_t perf_id;
    };
    class out_table {
    public:
        int depth;
        struct timeval time;
        uint64_t during_us;
        std::string func;
        std::unordered_map<std::string, uint64_t> event_map; // <event, counter>
    };
    char *infile;
    char *outfile;
    std::unordered_map<uint64_t, std::string> header_map;
    std::vector<std::shared_ptr<out_table>> out_vec;
    int calu_perf_info(Json::Value &root, std::unordered_map<std::string, uint64_t> &event_map);
    std::ofstream out;
    Json::StreamWriterBuilder streamWriter;
    Json::StreamWriter* jsonWriter;

public:
    parser(char *in, char *out) : infile(in), outfile(out) {};
    int profile_parser();
    int output_perf_file();
};

int parser::profile_parser() {
    int ret;
    char inbuf[1024];
    struct header_format *header;
    int in = open(infile, O_RDONLY);
    if (in < 0) {
        std::cout << "open " << infile <<" failed" << std::endl;
        return in;
    }
    ret = read(in, inbuf, strlen(PERF_PROFILE_HEADER) + 1);
    if (ret < 0) {
        std::cout << "Read " << infile << " header magic failed" << std::endl;
        return ret;
    }
    if (strcmp(inbuf, PERF_PROFILE_HEADER)) {
        std::cout <<"Bad magic" << std::endl;
        return -1;
    }
    /*read header*/
    while (1) {
        ret = read(in, inbuf, sizeof(struct header_format));
        if (ret != sizeof(struct header_format)) {
            std::cout << "Read header failed" << std::endl;
            return ret;
        } else if (!strncmp(inbuf, PERF_PROFILE_TEXT, NAME_MAX_LEN)) {
            std::cout << "header parse pass, start parse TEXT" << std::endl;
            break;
        } else {
            header = (struct header_format *)inbuf;
            header_map[header->perf_id] = header->event_name;
            std::cout << "perf_id:" << header->perf_id << ",name: "<< header_map[header->perf_id] << std::endl;
        }
    }
    /*read text*/
    while (1) {
        ret = read(in, inbuf, sizeof(struct output_format));
        if (ret != sizeof(struct output_format)) {
            // std::cout << "Read text failed" << std::endl;
            break;
        }
        struct output_format *of = (struct output_format *)inbuf;
        // uint64_t time = of->rf.time.tv_sec * 1000000 + of->rf.time.tv_usec;
        std::shared_ptr<out_table> ot = std::make_shared<out_table>();
        ot->time = of->rf.time;
        ot->func = of->func_name;
        ot->during_us = of->during_us;
        ot->depth = of->depth;
        for (uint64_t i = 0; i < of->rf.nr; i++) {
            ot->event_map[header_map[of->rf.values[i].id]] = of->rf.values[i].value;
        }
        out_vec.push_back(ot);
    }
    return 0;
}

int parser::output_perf_file() {
    out.open(outfile, std::ios::trunc | std::ios::out);
    if (!out.is_open()) {
        std::cout << "open " << outfile << " failed" << std::endl;
        return -1;
    }

    streamWriter["emitUTF8"] = true;
    streamWriter.settings_["precision"] = 2;
    jsonWriter = streamWriter.newStreamWriter();
    Json::Value root(Json::arrayValue);
    /*write output file*/
    for (auto item : out_vec) {
        Json::Value elem;
        elem["timestamp"] = std::to_string(item->time.tv_sec) + "." + std::to_string(item->time.tv_usec);
        elem["function"] = item->func;
        elem["during_us"] = item->during_us;
        elem["depth"] = item->depth;
        for (auto event: item->event_map) {
            elem["perf"][event.first] = event.second;
        }
        calu_perf_info(elem, item->event_map);
        root.append(elem);
    }

    jsonWriter->write(root, &out);
    return 0;
}

int parser::calu_perf_info(Json::Value &root, std::unordered_map<std::string, uint64_t> &event_map) {
    if (event_map.count("context-switches")) {
        root["perf"]["context-switches"] = event_map["context-switches"];
    }
    if (event_map.count("migrations")) {
        root["perf"]["migrations"] = event_map["migrations"];
    }
    if (event_map.count("page-faults")) {
        root["perf"]["page-faults"] = event_map["page-faults"];
    }
    if (event_map.count("instructions") && event_map.count("cycles")) {
        float ipc = (float)event_map["instructions"]/event_map["cycles"];
        root["perf"]["IPC"] = ipc;
    }
    if (event_map.count("stalled-cycles-frontend") && event_map.count("cycles")) {
        float frontend = (float)event_map["stalled-cycles-frontend"]/event_map["cycles"];
        frontend *= 100.0;
        root["perf"]["Frontend_stall"] = frontend;
    }
    if (event_map.count("stalled-cycles-backend") && event_map.count("cycles")) {
        float backend = (float)event_map["stalled-cycles-backend"]/event_map["cycles"];
        backend *= 100.0;
        root["perf"]["Backend_stall"] = backend;
    }
    if (event_map.count("L1-dcache-load-misses") && event_map.count("L1-dcache-loads")) {
        float l1d_miss = (float)event_map["L1-dcache-load-misses"]/event_map["L1-dcache-loads"];
        l1d_miss *= 100.0;
        root["perf"]["L1D_MISS_PERCENT"] = l1d_miss;
    }
    if (event_map.count("l2d_cache_refill") && event_map.count("l2d_cache")) {
        float l2d_miss = (float)event_map["l2d_cache_refill"]/event_map["l2d_cache"];
        l2d_miss *= 100.0;
        root["perf"]["L2D_MISS_PERCENT"] = l2d_miss;
    }
    if (event_map.count("l3d_cache_refill") && event_map.count("l3d_cache")) {
        float l3d_miss = (float)event_map["l3d_cache_refill"]/event_map["l3d_cache"];
        l3d_miss *= 100.0;
        root["perf"]["L3D_MISS_PERCENT"] = l3d_miss;
    }
    if (event_map.count("LLC-load-misses") && event_map.count("LLC-loads")) {
        float llc_miss = (float)event_map["LLC-load-misses"]/event_map["LLC-loads"];
        llc_miss *= 100.0;
        root["perf"]["LLC_MISS_PERCENT"] = llc_miss;
    }
    if (event_map.count("iTLB-load-misses") && event_map.count("iTLB-loads")) {
        float itlb_miss = (float)event_map["iTLB-load-misses"]/event_map["iTLB-loads"];
        itlb_miss *= 100.0;
        root["perf"]["ITLB_MISS_PERCENT"] = itlb_miss;
    }
    if (event_map.count("dTLB-load-misses") && event_map.count("dTLB-loads")) {
        float dtlb_miss = (float)event_map["dTLB-load-misses"]/event_map["dTLB-loads"];
        dtlb_miss *= 100.0;
        root["perf"]["DTLB_MISS_PERCENT"] = dtlb_miss;
    }
    if (event_map.count("branch-misses") && event_map.count("branches")) {
        float br_miss = (float)event_map["branch-misses"]/event_map["branches"];
        br_miss *= 100.0;
        root["perf"]["BRANCH_MISS_PERCENT"] = br_miss;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int opt;
    char *profile_file = nullptr;
    char *output_file = nullptr;

    while ((opt = getopt(argc, argv, "i:o:")) != -1) {
        switch (opt) {
            case 'i':
                profile_file = optarg;
            break;
            case 'o':
                output_file = optarg;
            break;
            default:
                std::cout << "Not support option \""<< opt << "\" , Use -i $inputfile and -o $outputfile" << std::endl;
            break;
        }
    }
    if (!(profile_file && output_file)) {
        std::cout << "Must specify profile_file and output_file" << std::endl;
        return -1;
    }
    parser perf_parser(profile_file, output_file);
    if (perf_parser.profile_parser() != 0) {
        std::cout << "parse file "<< profile_file << " failed" << std::endl;
        return -2;
    }
    if (perf_parser.output_perf_file() != 0) {
        std::cout << "Output "<< output_file << "failed" << std::endl;
        return -3;
    }
    return 0;
}