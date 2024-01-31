#include "common.h"
#include "inject_info.h"

inject_parser::inject_parser(const std::string &json) {
    Json::CharReaderBuilder builder;
    std::string errs;
    std::ifstream jsonFile(json);
    if (!jsonFile.is_open()) {
        CODE_INJECT_ERR("Open main config:%s failed\n", json.c_str());
        throw std::runtime_error("open json");
    }

    if (!Json::parseFromStream(builder, jsonFile, &root, &errs)) {
        CODE_INJECT_ERR("Parse main config %s failed\n", json.c_str());
        jsonFile.close();
        throw std::runtime_error("Parse json");
    }
    config_file = json;
    jsonFile.close();
    pid = -1;
}

bool inject_parser::parse_inject_config() {
    try {
        CODE_INJECT_INFO("parse_main_config main file:%s\n", config_file.c_str());
        hooker.elf_path = search_key(root, "injector-path").asString();
        hooker.sym_name = search_key(root, "injector-func").asString();
        helper.elf_path = search_key(root, "helper-path").asString();
        helper.sym_name = search_key(root, "helper-func").asString();
        pid = search_key(root, "pid").asInt();
        if (pid <= 0) {
            CODE_INJECT_ERR("Incorrect PID number:%d\n", pid);
            return false;
        }
        CODE_INJECT_INFO("hooker: %s:%s\n", hooker.elf_path.c_str(), hooker.sym_name.c_str());
        CODE_INJECT_INFO("helper: %s:%s\n", helper.elf_path.c_str(), helper.sym_name.c_str());
        auto injects = search_key(root, "inject-list");
        for (uint32_t i = 0; i < injects.size(); ++i) {
            Json::Value inject = injects[i];
            std::shared_ptr<inject_point> point = std::make_shared<inject_point>();
            point->target.elf_path = search_key(inject, "target_lib_path").asString();
            point->target.sym_name = search_key(inject, "target_func").asString();
            point->inject.elf_path = search_key(inject, "inject_lib_path").asString();
            point->inject.sym_name = search_key(inject, "inject_func").asString();
            point->tid = search_key(inject, "tid").asInt();
            if (point->tid <= 0) {
                CODE_INJECT_ERR("Incorrect TID number:%d\n", point->tid);
                return false;
            }
            point->helper_mode = search_key(inject, "helper_mode").asBool();
            point->orgi_callback = search_key(inject, "orgi_callback").asBool();
            if (point->helper_mode)
                point->hook_return = search_key(inject, "hook_return").asBool();
            else
                point->hook_return = false;
            CODE_INJECT_INFO("inject point: %s:%s, target point: %s:%s, helper_mode:%d, orgi_callback:%d, hook_return:%d, target_tid:%d\n",
                            point->inject.elf_path.c_str(), point->inject.sym_name.c_str(), point->target.elf_path.c_str(),
                            point->target.sym_name.c_str(), point->helper_mode, point->orgi_callback, point->hook_return, point->tid);
            targets.emplace_back(point);
        }
    } catch (const std::exception& e) {
        CODE_INJECT_ERR("Exception caught: %s in %s\n", e.what(), config_file.c_str());
        return false;
    }
    return true;
}

Json::Value inject_parser::search_key(Json::Value &root, const std::string &key) {
    if (root.isMember(key)) {
        return root[key];
    }
    throw std::runtime_error("Not found key");
}
