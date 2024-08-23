import json
import re
import subprocess
import os
import copy
import pickle
import sys
from pathlib import Path
from pprint import pprint


def save_slices(source_path, save_path, merge_slices, model, vul_api_line_name, save_location_path):
    # model表示是否在保存时添加上行号,1表示要
    filec = open(source_path, "r")  # 打开c原文件
    files = open(save_path, "a")  # 打开要写入的文件
    serial_number = 0  # 每个切片的序号
    lines = filec.readlines()  # read the source of c

    flag = 0
    for slices in merge_slices:
        index = slices.index(vul_api_line_name[serial_number][1])
        if slices[0] == 7580 and slices[1] == 7583:
            flag = 1
        else:
            flag = 0
        files.write(
            "serial number:" + str(serial_number) + " vul_api_line:" + str(vul_api_line_name[serial_number][1]) + " " +
            vul_api_line_name[serial_number][0] + "\n")  # 写入每一个切片的序号
        for i,node in enumerate(slices):  # 加上行号后打印出来
            if flag:
                print(node,"++++", slices)
            if model == 1:
                files.write(str(node) + " " + lines[node - 1].lstrip())
                if i > index+1:
                    break
            else:
                files.write(lines[node - 1].lstrip())
                if i > index+1:
                    break
        files.write("2\n")  # 为了统一格式，打上标签2，表示未知
        files.write("------------------------------\n")
        serial_number = serial_number + 1
    with open(save_location_path, "wb") as file:  # 保存位置文件
        pickle.dump(vul_api_line_name, file)


def bfs_slices(id, direction, nodes, methods, api_info):
    print("bfs_slices")
    methods_line = {}  # 行号和method节点的映射
    flag = set()  # 防止出现含环的情况
    q = [id]
    slices_lines = list()
    while q:
        index = q.pop(0)  # 弹出一个元素
        if index in flag:
            continue
        flag.add(index)
        if nodes[index]["_label"] == "CALL" and nodes[index]["id"] != id:  # 如果节点是call类型的节点，则需要获得其参数的位置,后面的条件是防止递归调用的情况
            lines = api_info[(nodes[index]["name"], index)]["arg_line"].split()  # 获取实参的位置
            # 使用正则表达式提取数字 [‘some(10)‘,‘some(20)‘,‘some(30)‘] --> [10, 20, 30]
            lines = [int(re.search(r'\d+', s).group()) for s in lines]
            slices_lines.extend(lines)  # 加入行号

            name = nodes[index]["name"]  # 获取节点的名字
            if name in methods:  # 如果这个节点是程序定义的节点，就需要递归进行bfs
                line = api_info[(name, index)]["lineNumber"]
                methods_line[line] = api_info[(name, index)]["callee_parameter_id"]

        # 将该节点相邻的节点加入到队列当中
        if len(nodes[index][direction]) > 0:
            next = nodes[index][direction]
            q.extend(next)
        if "lineNumber" in nodes[index]:
            slices_lines.append(nodes[index]["lineNumber"])
    return slices_lines, methods_line


# 建立一个id和method parameter的映射


def get_slice(vul_api_id, nodes, methods, api_info, depth, num):  # 对一组id进行切片
    merge_slices = list()
    if depth > 2 or num > 200:  # 减枝
        print(num,"num")
        return []
    for id in vul_api_id:
        back_slices, back_methods_line = bfs_slices(id, "backward_node", nodes, methods,
                                                    api_info)  # get the backward slices

        front_slices, front_methods_line = bfs_slices(id, "forward_node", nodes, methods,
                                                      api_info)  # get the forward slices
        methods_line = {**front_methods_line, **back_methods_line}  # 合并两个字典

        temp = back_slices + front_slices  # merge the slices
        unique_list = list(set(temp))  # 去重
        sorted_list = sorted(unique_list)  # 排序，因为是同一个函数，所以可以进行排序
        # 递归调用get_slice,以处理外部函数
        for line in methods_line:
            id_list = methods_line[line]
            # id_slices 是一个二维列表，需要将其变为一维列表
            id_slices = get_slice(id_list, nodes, methods, api_info, depth + 1, len(sorted_list))

            if len(id_slices) == 0:
                break
            slices = [item for sublist in id_slices for item in sublist]  # 通过列表推倒式将二维列表变为一维列表
            index_to_insert = 1  # 要插入的位置
            for info in sorted_list:
                if info == line:
                    sorted_list[index_to_insert:index_to_insert] = slices  # 将slices插入进该位置
                    break
                else:
                    index_to_insert = index_to_insert + 1
        # sorted_list = list(set(sorted_list))

        result = list()
        for i in range(len(sorted_list)):  # 去除可能存在的重复项 [1,2,2,3,3,3,3,4,6]
            if i + 1 < len(sorted_list) and sorted_list[i] == sorted_list[i + 1]:
                continue
            else:
                result.append(sorted_list[i])
        merge_slices.append(result)
    return merge_slices  # 返回的是行号


def get_method_flag(id, nodes):  # 该函数也是bfs，不过不是为了切片，而是为了判读危险函数的切片中的变量是否来自函数的参数
    print("get_method_flag")
    flag = set()  # 防止出现含环的情况
    parameter_index = list()  # 函数参数
    q = [id]
    while q:
        index = q.pop(0)  # 弹出一个元素
        if index in flag:  # 防止重复使用
            continue
        flag.add(index)  # 标记一下这个id节点已经使用过了
        if nodes[index]["_label"] == "METHOD_PARAMETER_IN" or nodes[index][
            "_label"] == "METHOD_PARAMETER_OUT":  # 如果此时遍历到的节点是函数的参数
            parameter_index.append(nodes[index]["index"])  # 加入该节点
        if len(nodes[index]["forward_node"]) > 0:  # 加入相邻的节点,只需要进行后向遍历
            next = nodes[index]["forward_node"]
            q.extend(next)

    return parameter_index


def deal_backforward_slice(nodes, method_chain, api_info, methods, vul_api_id, path):
    # 该函数用来处理回溯函数切片， method_chain是一个字典 {45: [[7, 39, 124]], 63: [[7, 39, 124]], 72: [[7, 39, 140]]}
    method_call = {}
    with open(path, 'r') as file:
        data = json.load(file)
    for d in data:
        method_call[d["_1"]] = set(d["_2"])
    merge_slices = []
    vul_api_id2 = []
    num = 0  # 用来计数
    for key in vul_api_id:
        num = num + 1
        chains = method_chain[key]  # 获取调用链
        for chain in chains:
            length = len(chain)
            vul_api_id2.append(key)
            vul_slice = get_slice([key], nodes, methods, api_info, 0, 0)  # 先对危险函数进行切片
            vul_slice = [item for sublist in vul_slice for item in sublist]  # 通过列表推倒式将二维列表变为一维列表
            for i in range(length):  # 遍历调用链  [45,39,7]
                parameter_index = get_method_flag(chain[i], nodes)  # 判断危险函数中的切片是否有来自父函数形参的
                if len(parameter_index) > 0 and i < length - 2:  # 如果索引大于0的话，则说明被引用了,则需要跳两个
                    # 获取相关的参数
                    name_method = nodes[chain[i + 1]]["name"]  # 获得一级函数
                    method_id = method_call[chain[i + 2]]  # 获得二级函数
                    for id in method_id:
                        name = nodes[id]["name"]
                        if name == name_method:  # 如果名字相同，则对这个id进行切片
                            slice = get_slice([id], nodes, methods, api_info, 0, 0)
                            slice = [item for sublist in slice for item in sublist]  # 通过列表推倒式将二维列表变为一维列表
                            method_line = nodes[id]["lineNumber"]  # 获取对应函数的lineNumber
                            # 将slice插入到vul_slice中
                            index_to_insert = 1  # 要插入的位置
                            for info in slice:
                                if info == method_line:
                                    slice[index_to_insert:index_to_insert] = vul_slice  # 将vul_slice插入进该位置
                                    break
                                else:
                                    index_to_insert = index_to_insert + 1
                            vul_slice = copy.deepcopy(slice)

                        if len(vul_slice) > 2000:  # 当这个切片太长了，直接停止切片
                            break
            merge_slices.append(vul_slice)
    vul_api_line_name = []
    for i in vul_api_id2:
        vul_api_line_name.append((nodes[i]["name"], nodes[i]["lineNumber"]))

    return merge_slices, vul_api_line_name


def cpgjson_to_cpgnode(cpgjson_path):
    with open(cpgjson_path, 'r') as file:
        data = json.load(file)  # data type: dict

    nodes = {}  # create a map

    for node in data:
        idx = node["id"]
        nodes[idx] = node
        nodes[idx]["backward_node"] = list()
        nodes[idx]["forward_node"] = list()
        nodes[idx]["side_type"] = list()
        nodes[idx]["side_value"] = list()

    return nodes

    ''' turn the cpgjson to the cpgnode

    change to the cpg node inorder to execute the bfs, every node has an id,
    which exists in the json.
    I add four index --> (backward_node, forward_node, side_type, side_value)

    args:
        cpgjson_path: the path of cpgjson which is imported from the joern

    return:
        the map of node: id --> node

    '''


def add_pdg_to_node(pdg_path, nodes):  # 将pdg中的信息加入到nodes当中，即构造pdg图
    with open(pdg_path, "r") as file:
        content = file.read()
        # sections = content.split('\n\n')  # 根据一个或多个空行划分
        # 使用正则表达式切割字符串
        digraph_blocks = re.split(r'\n(?=digraph)', content.strip())
    method = list()  # 用来存放method节点
    for content in digraph_blocks:  # 对每一个函数进行操作, such as [println, func]
        method.append(content.split()[1][1:-1])
        matches = re.findall(r'(\d+)" -> "(\d+)"  \[ label = "(\w+): (.*)"\]', content)  # type: list

        for match in matches:  # （前向节点，后向节点，类型，值）
            forward_node, backward_node, side_type, side_value = match
            # if side_type == "DDG":
            forward_node = int(forward_node)
            backward_node = int(backward_node)
            nodes[forward_node]["backward_node"].append(backward_node)
            nodes[backward_node]["forward_node"].append(forward_node)
            nodes[forward_node]["side_type"].append(side_type)
            nodes[forward_node]["side_value"].append(side_value)
    return nodes, method

    ''' add the pdg information to node

    Firstly, using the regular expressions to match,
    such as: [('25', '65', 'DDG', 'dataBuffer'), ('25', '65', 'DDG', "memset(dataBuffer, 'A', 99)")]
    then add the pgd information to the node

    args:
        pdg_path: the path of pdg
        nodes: the nodes from cpgjson_to_cpgnode()

    return:
        the nodes have extra info
    '''


def dfs_method_chain(method_id, method_map, res, method_chain: list, depth):
    if depth > 7:
        return method_chain
    temp = method_map[method_id]  # 获取调用method_id的方法的id
    if len(temp) == 0 or len(method_chain) > 10:  # 如果递归到头，就存储一下结果, 并且如果大于chain大于10，则停止
        method_chain.append(res)
        return method_chain
    for id in temp:
        res.append(id)
        method_chain = dfs_method_chain(id, method_map, copy.deepcopy(res), copy.deepcopy(method_chain),
                                        depth + 1)  # 注意要用深拷贝
        res.pop()

    return method_chain


def get_method_chain(method_chain_path, vul_api_id, api_info, nodes):  # 存储的是id
    # {call: caller}
    call_method_map = {}
    method_map = {}

    with open(method_chain_path, 'r') as file:
        data = json.load(file)  # data type: list, 某一个方法被其他方法调用，都是method类型

    for id in vul_api_id:  # 遍历危险函数的id
        method_id = api_info[(nodes[id]["name"], id)]["callee_id"]
        call_method_map[id] = method_id  # 使得危险函数id和其父函数id作映射

    for method in data:  # 某一个method节点被其他method节点调用的映射
        method_map[method["_1"]] = list(set(method["_2"]))  # 为了去重

    method_chain = {}

    for id in vul_api_id:
        temp = call_method_map[id]  # 取出其父函数id
        res = dfs_method_chain(temp, method_map, [], [], 0)

        for sub_list in res:
            sub_list.insert(0, temp)  # 加上危险函数的父函数的id
            sub_list.insert(0, id)  # 再加上自己的id
        method_chain[id] = res
    return method_chain  # {45: [[45, 39, 7]], 63: [[63, 39, 7]], 72: [[72, 39, 7]]}


def deal_view(method_chain, nodes, vul_api_id, path):
    vul_all = {}
    for id in vul_api_id:
        temp = method_chain[id]  # [[]]
        count = 0
        for i in temp:
            name_list2 = [nodes[j]["name"] for j in i]
            linenumber = nodes[id]["lineNumber"]
            name = nodes[id]["name"]
            vul_all[name + "|" + str(linenumber) + "|" + str(count + 1)] = name_list2
            count = count + 1
    # 将method chain写入到文件中,供前端使用
    with open(path, 'wb') as file:
        # 使用pickle的dump函数将列表序列化到文件
        pickle.dump(vul_all, file)
    # {'memset|12': ['memset', 'func'], 'memset|19': ['memset', 'func'], 'memmove|21': ['memmove', 'func']}
    # {673: [[673, 10324], [673, 669]], 9894: [[9894, 9858, 10752, 10958]], 10330: [[10330, 10324], [10330, 669]]}


def get_vul_api_id(api_info):  # 获得c语言元源程序中的危险函数的信息，api_info是joern获得的相关函数的信息
    vul_api_id = []
    vul_api_line = []
    file = open("../data/api.txt", "r")  # api.txt是敏感函数列表
    data_set = set()
    for line in file:
        line = line.strip()
        data_set.add(line)  # 将api.txt中的内容取出放到data_set中
    for key in api_info:
        if key[0] in data_set:
            vul_api_id.append(api_info[key]["id"])
            vul_api_line.append((api_info[key]['name'], api_info[key]["lineNumber"]))  # (name,lineNumber)
    return vul_api_id, vul_api_line


def get_all_api(api_path):
    api_info = {}
    with open(api_path, 'r') as file:
        content = file.read().replace("]\n[", ",\n")
        data = json.loads(content)  # data type: list
    for api in data:
        api_info[(api["_3"], api["_1"])] = {"id": api["_1"], "lineNumber": api["_2"], "code": api["_4"],
                                            "arg_line": api["_5"], "arg_id": api["_6"], "callee_id": api["_7"],
                                            "callee_parameter_id": api["_8"],
                                            "name": api["_3"]}  # api["_7"] : list [100, 101, 102]
    return api_info


# 去除c语言文件的注释， 对源文件进行修改
def remove_comments_c_style(filename):  # arg: filename => 表示要去除注释的c语言的文件名
    bds0 = '//.*'  # 标准匹配单行注释
    bds1 = '\/\*(?:[^\*]|\*+[^\/\*])*\*+\/'  # 标准匹配多行注释  可匹配跨行注释

    target1 = re.compile(bds0)  # 单行注释
    targetn = re.compile(bds1)  # 编译正则表达式

    # 读取源文件
    with open(filename, 'r', encoding='utf-8') as file:
        source_code = file.read()

    comment1 = target1.findall(source_code)  # 得到单行注释
    commentn = targetn.findall(source_code)  # 得到多行注释
    comments = comment1 + commentn  # 得到所有的注释

    for i in comments:
        source_code = source_code.replace(i, '')  # 将注释替换为空字符串

    # 写回到源文件
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(source_code)

    print("注释去除完成")


# 该函数用于检测某些文件是否存在，如果存在则删除
def file_exists(file_path):  # file_path 是文件路径的集合列表
    # 检查文件是否存在
    for file in file_path:
        if os.path.isfile(file):
            try:
                os.remove(file)
                print(f'文件 {file} 已被删除。')
            except OSError as e:
                print(f'删除文件时出错: {e.strerror}')
        else:
            print(f'文件 {file} 不存在。')


def exc_scan_scala(scala_path, source_path):
    exc_content = f"importCode(\"{source_path}\", \"a\")\n"  # 构造查询语句

    # 需要替换的行号，从1开始计数
    line_to_replace = 7

    # 读取文件内容到内存
    with open(scala_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    # 检查行号是否超出文件行数范围
    if 0 < line_to_replace <= len(lines):

        if lines[line_to_replace - 1][0:10] != "importCode":
            print("请检查scala文件！！！")
            return 0

        # 替换指定行的内容（行号减1得到列表索引）
        lines[line_to_replace - 1] = exc_content

        # 将修改后的内容写回文件
        with open(scala_path, 'w', encoding='utf-8') as file:
            file.writelines(lines)
    else:
        print(f"文件中没有行号为 {line_to_replace} 的行")

    # 执行get_all_call.scala文件
    os.system(f"..\joern-cli\joern --script {scala_path}")
    print("get_all_call.scala执行成功")


def main(cpgjson_path, pdg_path, scan_api_path, source_path, save_path, method_chain_path, save_location_path,
         vul_all_path, method_call_path):
    # 判断各个文件是否存在，如果不存在，则退出程序
    if (not os.path.exists(cpgjson_path)) or (not os.path.exists(pdg_path)) or (not os.path.exists(scan_api_path)):
        print(cpgjson_path, os.path.exists(cpgjson_path))
        print(pdg_path, os.path.exists(pdg_path))
        print(scan_api_path, os.path.exists(scan_api_path))
        print("文件路径出错，请检查文件路径...")
        return 0
    # 1.get info of file
    nodes = cpgjson_to_cpgnode(cpgjson_path)  # 获得程序的信息
    nodes, methods = add_pdg_to_node(pdg_path, nodes)  # 将pdg图添加到nodes中
    # 2.get the id of api
    api_info = get_all_api(scan_api_path)  # 获得api函数的名称
    vul_api_id, vul_api_line_name = get_vul_api_id(api_info)  # 获得危险函数的id和line

    method_chain = get_method_chain(method_chain_path, vul_api_id, api_info, nodes)  # 获得函数调用链

    # 3.get the slices"../data/joern_data/method_call.json"
    merge_slices, vul_api_line_name = deal_backforward_slice(nodes, method_chain, api_info, methods, vul_api_id,
                                                             method_call_path)
    # merge_slices = get_slice(vul_api_id, nodes, methods, api_info, 0)
    save_slices(source_path, save_path, merge_slices, 0, vul_api_line_name, save_location_path)
    deal_view(method_chain, nodes, vul_api_id, vul_all_path)
    return vul_api_line_name  # 返回危险函数的行号，以提供给图形化静脉内处使用 例：[('memset', 20), ('memset', 27), ('memmove', 29)]


def change_file_name(file_name):
    # 修改文件名
    path = {
        "../data/joern_data/cpg_json.json",
        "../data/joern_data/pdg_txt.txt",
        "../data/joern_data/scan_api.txt",
        "../data/joern_data/method_chain.json",
        "../data/joern_data/method_call.json",
    }
    for p in path:
        if not os.path.exists(p):
            file_exists(path)
            return False
    for current_file_path in path:
        file_name_with_extension = os.path.basename(current_file_path)  # 获取文件名
        file_name_without_extension, _ = os.path.splitext(file_name_with_extension)  # 去除扩展名
        new_name = file_name_without_extension + "_" + file_name + _
        directory = os.path.dirname(current_file_path)
        new_file_path = os.path.join(directory, new_name).replace("\\", "/")
        print("---", current_file_path, new_file_path)
        os.rename(current_file_path, new_file_path)
    return True


def exc_main(analyse_file_name):
    file_name_with_extension = os.path.basename(analyse_file_name)  # 获取文件名
    file_name, _ = os.path.splitext(file_name_with_extension)  # 去除扩展名
    gen_cpg_pdg = "../static_detection/gen_cpg_pdg.scala"  # 即joern执行文件路径名称
    source_path = analyse_file_name  # 要检测的c语言源文件
    save_path = f"../data/test/test_slices_{file_name}.txt"  # 要保存的切片路径
    path = [f"../data/joern_data/scan_api_{file_name}.txt",
            f"../data/joern_data/cpg_json_{file_name}.json",
            f"../data/joern_data/pdg_txt_{file_name}.txt",
            f"../data/joern_data/method_call_{file_name}.json",
            f'../data/view/vul_all_{file_name}.pkl',
            f"../data/test/test_slices_{file_name}.txt",
            f"../data/test/test_location_path_{file_name}.pkl",
            f"../data/joern_data/method_chain_{file_name}.json"]
    # '../data/view/vul_all.pkl'
    flag = 1  # 令牌
    if flag:
        file_exists(path)  # 检查文件是否存在
        remove_comments_c_style(source_path)  # 去除c语言注释
        exc_scan_scala(gen_cpg_pdg, source_path)  # 生成cpg、pdg图

    is_success = change_file_name(file_name)
    if not is_success:
        return []
    cpg_json_path = f"../data/joern_data/cpg_json_{file_name}.json"  # cpg图信息的文件
    pdg_path = f"../data/joern_data/pdg_txt_{file_name}.txt"  # pdg图信息的文件
    scan_api_path = f"../data/joern_data/scan_api_{file_name}.txt"  # 扫描到的api的信息名称
    method_chain_path = f"../data/joern_data/method_chain_{file_name}.json"  # 方法链的文件
    save_location_path = f"../data/test/test_location_path_{file_name}.pkl"  # 存放测试数据的危险函数的location信息
    vul_all_path = f"../data/view/vul_all_{file_name}.pkl"
    method_call_path = f"../data/joern_data/method_call_{file_name}.json"
    vul_api_line_name_path = f"../data/test/vul_api_line_name_{file_name}.pkl"
    vul_api_line_name = main(cpg_json_path, pdg_path, scan_api_path, source_path, save_path, method_chain_path,
                             save_location_path, vul_all_path, method_call_path)
    with open(vul_api_line_name_path, "wb") as file:  # 存储好结果
        pickle.dump(vul_api_line_name, file)

    return vul_api_line_name


if __name__ == "__main__":
    source_path = "../view/cgibin.c"
    exc_main(sys.argv[1])
