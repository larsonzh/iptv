#!/bin/sh
# lz_iptv.sh v2.0.0
# By LZ 妙妙呜 (larsonzhang@gmail.com)

# shellcheck disable=SC3023

## 启动IPTV服务命令：  /jffs/scripts/lz/lz_iptv.sh
## 停止IPTV服务命令：  /jffs/scripts/lz/lz_iptv.sh stop
## 解除IPTV脚本卡锁：  /jffs/scripts/lz/lz_iptv.sh unlock
## 从路由器中删除此脚本前，请执行一次“停止IPTV服务命令”以释放脚本
## 曾经分配过的系统资源。

## 由于华硕及梅林固件路由器内部机制限制，双通道接入两路IPTV网络时，
## 仅能使其中一路IPTV的机顶盒可以全功能完整状态工作，能够实现广电
## 视频节目直播、回放和点播等功能。脚本目前只支持IPv4网络地址。

# BEIGIN

## --------------------------用户参数设置区--------------------------

## 互联网线路接入口（1--第一WAN口；2--第二WAN口）
## 缺省为第一WAN口。
internet_wan=1

## 路由器IPTV线路接入口（1--第一WAN口；2--第二WAN口）
## 缺省为第一WAN口。
iptv_wan=1

## IPTV机顶盒获取IP地址方式（1--DHCP或IPoE；2--静态IP；3--PPPoE）
## 缺省为DHCP或IPoE。
iptv_get_ip_mode=1

## IPTV机顶盒访问IPTV线路方式（1--直连IPTV线路；2--按服务地址访问）
## 缺省为直连IPTV线路。
iptv_access_mode=1

## hnd平台机型核心网桥组播控制方式（0--禁用；1--标准方式；2--阻塞方式）
## 缺省为阻塞方式。
## 此参数仅对hnd/axhnd/axhnd.675x等hnd平台机型路由器有效，IPTV机顶盒
## 不能正常播放节目时可尝试调整此参数。
hnd_br0_bcmmcast_mode=2

## IPTV机顶盒内网IP地址列表（可逐行填入多个机顶盒地址）
cat > /tmp/lz_iptv_box_ip.lst <<EOF
## 在地址条目前加#注释符，可使该条目失效
10.0.0.46	# 机顶盒-1
#10.0.0.101	# 机顶盒-2

EOF

## IPTV网络服务IP网址/网段列表（可逐行填入多个地址条目）
## 仅在机顶盒访问IPTV线路方式为“按服务地址访问”时使用
cat > /tmp/lz_iptv_ip_addr.lst <<EOF
## 在地址条目前加#注释符，可使该条目失效

EOF

## --------------------------参数设置区结束--------------------------


## 版本号
LZ_VERSION=v2.0.0

# 项目文件部署路径
PATH_LZ="${0%/*}"
[ "${PATH_LZ:0:1}" != '/' ] && PATH_LZ="$( pwd )${PATH_LZ#*.}"

## 项目临时文件目录
PATH_TMP="${PATH_LZ}/tmp"

## 项目标识及项目文件名
PROJECT_ID="lz_iptv"
PROJECT_FILENAME="${PROJECT_ID}.sh"

## 自启动引导文件部署路径
PATH_BOOTLOADER="/jffs/scripts"

## 自启动引导文件名
BOOTLOADER_NAME="firewall-start"

## 第一WAN口路由表ID号
WAN0="100"

## 第二WAN口路由表ID号
WAN1="200"

## IPTV路由表ID
LZ_IPTV="888"

## IPTV规则优先级
IP_RULE_PRIO_IPTV="888"

## 策略规则基础优先级--25000（IP_RULE_PRIO）
IP_RULE_PRIO="25000"

## 负载均衡用路由器内网网段数据集合
BALANCE_IP_SET="lz_iptv_balance_ipsets"

## 系统事件记录文件
SYSLOG="/tmp/syslog.log"

## iptables --match-set针对不同硬件类型选项设置的操作符宏变量
MATCH_SET='--match-set'

HAMMER="$( echo "${1}" | tr '[:A-Z:]' '[:a-z:]' )"
STOP_RUN="stop"
FORCED_UNLOCKING="unlock"

PATH_LOCK="/var/lock"
LOCK_FILE="${PATH_LOCK}/lz_rule.lock"
LOCK_FILE_ID=555
INSTANCE_LIST="${PATH_LOCK}/lz_iptv_instance.lock"

lzdate() { date +"%F %T"; }

set_lock() {
    [ "${HAMMER}" = "${FORCED_UNLOCKING}" ] && return "1"
    echo "lz_iptv_${HAMMER}" >> "${INSTANCE_LIST}"
    [ ! -d "${PATH_LOCK}" ] && { mkdir -p "${PATH_LOCK}" > /dev/null 2>&1; chmod 777 "${PATH_LOCK}" > /dev/null 2>&1; }
    eval "exec ${LOCK_FILE_ID}<>${LOCK_FILE}"
    flock -x "${LOCK_FILE_ID}" > /dev/null 2>&1
    sed -i -e '/^$/d' -e '/^[ ]*$/d' -e '1d' "${INSTANCE_LIST}" > /dev/null 2>&1
    if grep -q 'lz_iptv_' "${INSTANCE_LIST}" 2> /dev/null; then
        [ "$( grep 'lz_iptv_' "${INSTANCE_LIST}" 2> /dev/null | sed -n 1p | sed -e 's/^[ ]*//g' -e 's/[ ]*$//g' )" = "lz_iptv_${HAMMER}" ] && {
            echo "$(lzdate)" [$$]: LZ IPTV Support service is being started by another instance. | tee -ai "${SYSLOG}" 2> /dev/null
            return "1"
        }
    fi
    return "0"
}

forced_unlock() {
    rm -f "${INSTANCE_LIST}" > /dev/null 2>&1
    if [ -f "${LOCK_FILE}" ]; then
        rm -f "${LOCK_FILE}" > /dev/null 2>&1
        echo "$(lzdate)" [$$]: Program synchronization lock has been successfully unlocked. | tee -ai "${SYSLOG}" 2> /dev/null
    else
        echo "$(lzdate)" [$$]: There is no program synchronization lock. | tee -ai "${SYSLOG}" 2> /dev/null
    fi
    return "0"
}

unset_lock() {
    [ "${HAMMER}" = "error" ] && return
    [ "${HAMMER}" = "${FORCED_UNLOCKING}" ] && forced_unlock && return
    [ -f "${INSTANCE_LIST}" ] && ! grep -q 'lz_iptv_' "${INSTANCE_LIST}" 2> /dev/null && rm -f "${INSTANCE_LIST}" > /dev/null 2>&1
    [ -f "${LOCK_FILE}" ] && flock -u "${LOCK_FILE_ID}" > /dev/null 2>&1
}

get_match_set() {
    case $( uname -m ) in
        armv7l)
            MATCH_SET='--match-set'
        ;;
        mips)
            MATCH_SET='--set'
        ;;
        aarch64)
            MATCH_SET='--match-set'
        ;;
        *)
            MATCH_SET='--match-set'
        ;;
    esac
}

## 处理系统负载均衡分流策略规则函数
## 输入项：
##     $1--规则优先级（150--ASUS原始；$(( IP_RULE_PRIO + 1 ))--脚本原定义）
##     全局常量
## 返回值：无
lz_sys_load_balance_control() {
    ## 删除路由前mangle表balance负载均衡规则链中脚本曾经插入的规则（避免系统原生负载均衡影响分流）
    if iptables -t mangle -L PREROUTING 2> /dev/null | grep -q balance; then
        local local_number="$( iptables -t mangle -L balance -v -n --line-numbers 2> /dev/null \
            | grep -w "${BALANCE_IP_SET}" \
            | cut -d " " -f 1 | grep -o '^[0-9]*$' | sort -nr )"
        local local_item_no=
        for local_item_no in ${local_number}
        do
            iptables -t mangle -D balance "${local_item_no}" > /dev/null 2>&1
        done
    fi
    ipset -q destroy "${BALANCE_IP_SET}"
    ## 调整策略规则路由数据库中负载均衡策略规则条目的优先级
    ## a.对固件系统中第一WAN口的负载均衡分流策略
    local local_sys_load_balance_wan0_exist="$( ip rule show | grep -ci "from all fwmark 0x80000000/0xf0000000" )"
    if [ "${local_sys_load_balance_wan0_exist}" -gt "0" ]; then
        until [ "${local_sys_load_balance_wan0_exist}" = "0" ]
        do
            ip rule show | grep -i "from all fwmark 0x80000000/0xf0000000" | awk -F: '{system("ip rule del prio "$1" > /dev/null 2>&1")}'
            local_sys_load_balance_wan0_exist="$( ip rule show | grep -ci "from all fwmark 0x80000000/0xf0000000" )"
        done
        ip rule add from all fwmark "0x80000000/0xf0000000" table "${WAN0}" prio "${1}" > /dev/null 2>&1
        ip route flush cache > /dev/null 2>&1
    fi
    ## b.对固件系统中第二WAN口的负载均衡分流策略
    local local_sys_load_balance_wan1_exist="$( ip rule show | grep -ci "from all fwmark 0x90000000/0xf0000000" )"
    if [ "${local_sys_load_balance_wan1_exist}" -gt "0" ]; then
        until [ "${local_sys_load_balance_wan1_exist}" = "0" ]
        do
            ip rule show | grep -i "from all fwmark 0x90000000/0xf0000000" | awk -F: '{system("ip rule del prio "$1" > /dev/null 2>&1")}'
            local_sys_load_balance_wan1_exist="$( ip rule show | grep -ci "from all fwmark 0x90000000/0xf0000000" )"
        done
        ip rule add from all fwmark "0x90000000/0xf0000000" table "${WAN1}" prio "${1}" > /dev/null 2>&1
        ip route flush cache > /dev/null 2>&1
    fi
}

## 清除系统策略路由库中已有规则
## 输入项：
##     $1--规则优先级
##     全局常量
## 返回值：无
lz_del_ip_rule() {
    local ip_rule_exist="$( ip rule show | grep -c "^${1}:" )"
    if [ "${ip_rule_exist}" -gt "0" ]; then
        until [ "${ip_rule_exist}" = "0" ]
        do
            ip rule show | awk -F: '$1 == "'"${1}"'" {system("ip rule del prio "$1" > /dev/null 2>&1")}'
            ip_rule_exist="$( ip rule show | grep -c "^${1}:" )"
        done
        ip route flush cache > /dev/null 2>&1
    fi
}

## 清除系统策略路由库中已有IPTV规则
lz_del_iptv_rule() {
    ## 清除系统策略路由库中已有规则
    ## 输入项：
    ##     $1--规则优先级
    ##     全局常量
    ## 返回值：无
    lz_del_ip_rule "${IP_RULE_PRIO_IPTV}"
    lz_del_ip_rule "$(( IP_RULE_PRIO - 1 ))"
    lz_del_ip_rule "${IP_RULE_PRIO}"
}

## 清空系统中已有IPTV路由表
lz_clear_iptv_route() {
    ip route show table "${LZ_IPTV}" | awk '{system("ip route del "$0"'" table ${LZ_IPTV} > /dev/null 2>&1"'")}'
    ip route flush cache > /dev/null 2>&1
}

## 生成IGMP代理配置文件
## 输入项：
##     $1--文件路径
##     $2--IGMP代理配置文件名
##     $3--IPTV线路在路由器内的接口设备ID
## 返回值：
##     0--成功
##     1--失败
lz_create_igmp_proxy_conf() {
    if [ -z "${1}" ] || [ -z "${2}" ] || [ -z "${3}" ]; then return "1"; fi;
    [ ! -d "${1}" ] && mkdir -p "${1}" > dev/null 2>&1
    cat > "${1}"/"${2}" <<EOF
phyint ${3} upstream ratelimit 0 threshold 1 altnet 0.0.0.0/0
phyint br0 downstream ratelimit 0 threshold 1
EOF
    [ ! -f "${1}/${2}" ] && return "1"
    return "0"
}

## 设置hnd/axhnd/axhnd.675x平台核心网桥IGMP接口函数
## 输入项：
##     $1--接口标识
##     $2--0：IGMP&MLD；1：IGMP；2：MLD
##     $3--0：disabled；1：standard；2：blocking
## 返回值：
##     0--成功
##     1--失败
lz_set_hnd_bcmmcast_if() {
    local reval="1"
    ! which bcmmcastctl > /dev/null 2>&1 && return "${reval}"
    [ "${2}" != "0" ] && [ "${2}" != "1" ] && [ "${2}" != "2" ] && return "${reval}"
    [ "${3}" != "0" ] && [ "${3}" != "1" ] && [ "${3}" != "2" ] && return "${reval}"
    [ -n "${1}" ] && {
        bcmmcastctl show 2> /dev/null | grep -w "${1}:" | grep -q MLD && {
            if [ "${2}" = "0" ] || [ "${2}" = "2" ]; then
                bcmmcastctl rate -i "${1}" -p 2 -r 0  > /dev/null 2>&1
                bcmmcastctl l2l -i "${1}" -p 2 -e 1  > /dev/null 2>&1
                bcmmcastctl mode -i "${1}" -p 2 -m "${3}" > /dev/null 2>&1 && let reval++
            fi
        }
        bcmmcastctl show 2> /dev/null | grep -w "${1}:" | grep -q IGMP && {
            if [ "${2}" = "0" ] || [ "${2}" = "1" ]; then
                bcmmcastctl rate -i "${1}" -p 1 -r 0  > /dev/null 2>&1
                bcmmcastctl l2l -i "${1}" -p 1 -e 1  > /dev/null 2>&1
                bcmmcastctl mode -i "${1}" -p 1 -m "${3}" > /dev/null 2>&1 && let reval++
            fi
        }
        [ "${2}" = "0" ] && {
            if [ "${reval}" = "3" ]; then reval="0"; else reval="1"; fi;
        }
        if [ "${2}" = "1" ] || [ "${2}" = "2" ]; then
            if [ "${reval}" = "2" ]; then reval="0"; else reval="1"; fi;
        fi
    }
    return "${reval}"
}

## 恢复系统原有igmpproxy参数
## 输入项：
##     $1--是否显示执行结果（1--显示；其它符号--禁止显示）
##     全局变量
## 返回值：无
lz_restore_sys_igmpproxy_parameters() {
    ## 获取系统原生第一WAN口的接口ID标识
    local iptv_ifname="$( nvram get "wan0_ifname" | grep -Eo 'vlan[0-9]*|eth[0-9]*' | sed -n 1p )"
    ## 获取igmpproxy进程信息
    local igmp_filename="$( ps | awk '!/awk/ && /igmpproxy/ && /\.conf/ {print $6; exit}' )"
    if [ -n "${igmp_filename}" ]; then
        ## 判断igmpproxy.conf是否存在
        if [ -f "${igmp_filename}" ]; then
            ## 判断接口是否存在
            if [ -z "${iptv_ifname}" ]; then
                ## 接口不存在，杀掉当前进程
                killall "igmpproxy" > /dev/null 2>&1
            ## 判断接口是否符合当前脚本参数设置
            elif ! grep "phyint" "${igmp_filename}" | grep "upstream" | grep -q "${iptv_ifname}"; then
                ## 不符合则需杀掉当前进程
                killall "igmpproxy" > /dev/null 2>&1
                ## 生成IGMP代理配置文件
                ## 输入项：
                ##     $1--文件路径
                ##     $2--IGMP代理配置文件名
                ##     $3--IPTV线路在路由器内的接口设备ID
                ## 返回值：
                ##     0--成功
                ##     1--失败
                lz_create_igmp_proxy_conf "/tmp" "igmpproxy.conf" "${iptv_ifname}"
                sleep "1s"
                ## 重新启动igmpproxy代理
                /usr/sbin/igmpproxy "/tmp/igmpproxy.conf" > /dev/null 2>&1
                if [ "${1}" = "1" ]; then
                    ## 再次获取igmpproxy进程信息
                    igmp_filename="$( ps | awk '!/awk/ && /igmpproxy/ && /\.conf/ {print $6; exit}' )"
                    if [ -n "${igmp_filename}" ]; then
                        echo "$(lzdate)" [$$]: IGMPPROXY service \( "${iptv_ifname}" \) is running. | tee -ai "${SYSLOG}" 2> /dev/null
                    fi
                fi
            else
                ## 判断是否使用的是系统原有路径的配置文件
                if [ "${igmp_filename}" != "/tmp/igmpproxy.conf" ]; then
                    ## 不符合则需杀掉当前进程
                    killall "igmpproxy" > /dev/null 2>&1
                    ## 生成IGMP代理配置文件
                    ## 输入项：
                    ##     $1--文件路径
                    ##     $2--IGMP代理配置文件名
                    ##     $3--IPTV线路在路由器内的接口设备ID
                    ## 返回值：
                    ##     0--成功
                    ##     1--失败
                    lz_create_igmp_proxy_conf "/tmp" "igmpproxy.conf" "${iptv_ifname}"
                    sleep "1s"
                    ## 重新启动igmpproxy代理
                    /usr/sbin/igmpproxy "/tmp/igmpproxy.conf" > /dev/null 2>&1
                fi
                if [ "${1}" = "1" ]; then
                    ## 再次获取igmpproxy进程信息
                    igmp_filename="$( ps | awk '!/awk/ && /igmpproxy/ && /\.conf/ {print $6; exit}' )"
                    if [ -n "${igmp_filename}" ]; then
                        echo "$(lzdate)" [$$]: IGMPPROXY service \( "${iptv_ifname}" \) is running. | tee -ai "${SYSLOG}" 2> /dev/null
                    fi
                fi
            fi
        else
            ## 当前进程的igmpproxy代理文件不存在的错误，需要杀掉当前进程
            killall "igmpproxy" > /dev/null 2>&1
            if [ -n "${iptv_ifname}" ]; then
                ## 生成IGMP代理配置文件
                ## 输入项：
                ##     $1--文件路径
                ##     $2--IGMP代理配置文件名
                ##     $3--IPTV线路在路由器内的接口设备ID
                ## 返回值：
                ##     0--成功
                ##     1--失败
                lz_create_igmp_proxy_conf "/tmp" "igmpproxy.conf" "${iptv_ifname}"
                sleep "1s"
                ## 重新启动igmpproxy代理
                /usr/sbin/igmpproxy "/tmp/igmpproxy.conf" > /dev/null 2>&1
                if [ "${1}" = "1" ]; then
                    ## 再次获取igmpproxy进程信息
                    igmp_filename="$( ps | awk '!/awk/ && /igmpproxy/ && /\.conf/ {print $6; exit}' )"
                    if [ -n "${igmp_filename}" ]; then
                        echo "$(lzdate)" [$$]: IGMPPROXY service \( "${iptv_ifname}" \) is running. | tee -ai "${SYSLOG}" 2> /dev/null
                    fi
                fi
            fi
        fi
    else
        ## hnd/axhnd/axhnd.675x平台机型无igmpproxy进程
        ## 设置hnd/axhnd/axhnd.675x平台核心网桥IGMP接口
        ## 输入项：
        ##     $1--接口标识
        ##     $2--0：IGMP&MLD；1：IGMP；2：MLD
        ##     $3--0：disabled；1：standard；2：blocking
        ## 返回值：
        ##     0--成功
        ##     1--失败
        lz_set_hnd_bcmmcast_if "br0" "0" "2"
    fi
    ## 清除脚本生成的IGMP代理配置文件
    if [ -f "${PATH_TMP}/igmpproxy.conf" ]; then
        rm -f "${PATH_TMP}/igmpproxy.conf" > /dev/null 2>&1
    fi
}

## 调整和更新udpxy参数
## 输入项：
##     $1--IPTV线路在路由器内的接口设备ID（vlanx，pppx，ethx，nnn--未知接口；x--数字编号）
##     $2--是否显示执行结果（1--显示；其它符号--禁止显示）
## 返回值：无
lz_djust_udpxy_parameters() {
    ## 校验输入项参数是否在取值范围内，否则退出
    local iptv_ifname="$( echo "${1}" | grep -Eo 'vlan[0-9]*|eth[0-9]*|ppp[0-9]*|nnn' )"
    [ -z "${iptv_ifname}" ] && return
    if [ "${iptv_ifname}" = "nnn" ]; then
        ## 获取系统原生第一WAN口的接口ID标识
        iptv_ifname="$( nvram get "wan0_ifname" | grep -Eo 'vlan[0-9]*|eth[0-9]*' | sed -n 1p )"
    fi
    ## 获取路由器本地IP地址
    local route_local_ip="$( /sbin/ifconfig "br0" | awk 'NR==2 {print $2}' | awk -F: '{print $2}' )"
    ## 获取udpxy进程信息
    local udpxy_item="$( ps | grep "udpxy" | grep '\-m' | sed -n 1p )"
    ## 获取udpxy端口号
    local udpxy_enable_x="$( nvram get "udpxy_enable_x" | grep -Eo '^[1-9][0-9]{0,4}$' | sed -n 1p )"
    ## 获取udpxy客户端数量
    local udpxy_clients="$( nvram get "udpxy_clients" | grep -Eo '^[1-9][0-9]{0,3}$' | sed -n 1p )"
    if [ -z "${udpxy_enable_x}" ]; then
        [ -n "${udpxy_item}" ] && killall "udpxy" > /dev/null 2>&1
    elif [ -n "${udpxy_item}" ]; then
        if ! echo "${udpxy_item}" | grep -q "${iptv_ifname}"; then
            killall "udpxy" > /dev/null 2>&1
            ## 重启udpxy服务
            if [ -n "${iptv_ifname}" ]; then
                /usr/sbin/udpxy -m "${iptv_ifname}" -p "${udpxy_enable_x}" -B "65536" -c "${udpxy_clients}" -a "br0" > /dev/null 2>&1
            fi
        fi
        if [ "${2}" = "1" ]; then
            ## 再次获取udpxy进程信息
            udpxy_item="$( ps | grep "udpxy" | grep '\-m' | sed -n 1p )"
            iptv_ifname="$( ps | grep "udpxy" | grep '\-m' | sed -n 1p | awk -F '\-m ' '{print $2}' | awk '{print $1}' )"
            if [ -n "${udpxy_item}" ]; then
                echo "$(lzdate)" [$$]: UDPXY service \( "${route_local_ip}:${udpxy_enable_x}" "${iptv_ifname}" \) is running. | tee -ai "${SYSLOG}" 2> /dev/null
            fi
        fi
    else
        if [ -n "${iptv_ifname}" ]; then
            ## 重启udpxy服务
            /usr/sbin/udpxy -m "${iptv_ifname}" -p "${udpxy_enable_x}" -B "65536" -c "${udpxy_clients}" -a "br0" > /dev/null 2>&1			
        fi
        if [ "${2}" = "1" ]; then
            ## 再次获取udpxy进程信息
            udpxy_item="$( ps | grep udpxy | grep '\-m' | sed -n 1p )"
            iptv_ifname="$( ps | grep udpxy | grep '\-m' | sed -n 1p | awk -F '\-m ' '{print $2}' | awk '{print $1}' )"
            if [ -n "${udpxy_item}" ]; then
                echo "$(lzdate)" [$$]: UDPXY service \( "${route_local_ip}:${udpxy_enable_x}" "${iptv_ifname}" \) is running. | tee -ai "${SYSLOG}" 2> /dev/null
            fi
        fi
    fi
}

## 恢复系统原有IPTV服务
## 输入项：
##     $1--是否显示执行结果（1--显示；其它符号--禁止显示）
## 返回值：无
lz_restore_sys_iptv_services() {
    ## 恢复系统原有igmpproxy参数
    ## 输入项：
    ##     $1--是否显示执行结果（1--显示；其它符号--禁止显示）
    ##     全局变量
    ## 返回值：无
    lz_restore_sys_igmpproxy_parameters "${1}"

    ## 恢复系统原有udpxy参数
    ## 调整和更新udpxy参数
    ## 输入项：
    ##     $1--IPTV线路在路由器内的接口设备ID（vlanx，pppx，ethx，nnn--未知接口；x--数字编号）
    ##     $2--是否显示执行结果（1--显示；其它符号--禁止显示）
    ## 返回值：无
    lz_djust_udpxy_parameters "nnn" "${1}"
}

## 清除firewall-start中脚本引导项
lz_clear_firewall_start_command() {
    if [ -f "${PATH_BOOTLOADER}/${BOOTLOADER_NAME}" ] && grep -q "${PROJECT_FILENAME}" "${PATH_BOOTLOADER}/${BOOTLOADER_NAME}"; then
        sed -i "/${PROJECT_FILENAME}/d" "${PATH_BOOTLOADER}/${BOOTLOADER_NAME}" > /dev/null 2>&1
    fi
}

## 创建事件接口
## 输入项：
##     $1--系统事件接口文件名
##     $2--待接口文件所在路径
##     $3--待接口文件名称
##     全局常量
## 返回值：
##     0--成功
##     1--失败
lz_create_event_interface() {
    [ ! -d "${PATH_BOOTLOADER}" ] && mkdir -p "${PATH_BOOTLOADER}"
    if [ ! -f "${PATH_BOOTLOADER}/${1}" ]; then
        cat > "${PATH_BOOTLOADER}/${1}" 2> /dev/null <<EOF_INTERFACE
#!/bin/sh
EOF_INTERFACE
    fi
    [ ! -f "${PATH_BOOTLOADER}/${1}" ] && return "1"
    if ! grep -m 1 '^.*$' "${PATH_BOOTLOADER}/${1}" | grep -q "#!/bin/sh"; then
        if [ "$( grep -c '^.*$' "${PATH_BOOTLOADER}/${1}" )" = "0" ]; then
            echo "#!/bin/sh" >> "${PATH_BOOTLOADER}/${1}"
        elif grep '^.*$' "${PATH_BOOTLOADER}/${1}" | grep -q "#!/bin/sh"; then
            sed -i -e '/!\/bin\/sh/d' -e '1i #!\/bin\/sh' "${PATH_BOOTLOADER}/${1}"
        else
            sed -i '1i #!\/bin\/sh' "${PATH_BOOTLOADER}/${1}"
        fi
    else
        ! grep -m 1 '^.*$' "${PATH_BOOTLOADER}/${1}" | grep -q "^#!/bin/sh" \
            && sed -i 'l1 s:^.*\(#!/bin/sh.*$\):\1/g' "${PATH_BOOTLOADER}/${1}"
    fi
    if ! grep -q "${2}/${3}" "${PATH_BOOTLOADER}/${1}"; then
        sed -i "/${3}/d" "${PATH_BOOTLOADER}/${1}"
        sed -i "\$a ${2}/${3} # Added by LZ" "${PATH_BOOTLOADER}/${1}"
    fi
    chmod +x "${PATH_BOOTLOADER}/${1}"
    ! grep -q "${2}/${3}" "${PATH_BOOTLOADER}/${1}" && return "1"
    return "0"
}

## 创建firewall-start启动文件并添加脚本引导项
lz_create_firewall_start_command() {
    ## 创建事件接口
    ## 输入项：
    ##     $1--系统事件接口文件名
    ##     $2--待接口文件所在路径
    ##     $3--待接口文件名称
    ##     全局常量
    ## 返回值：
    ##     0--成功
    ##     1--失败
    lz_create_event_interface "${BOOTLOADER_NAME}" "${PATH_LZ}" "${PROJECT_FILENAME}"
}

## 向系统策略路由库中添加双向访问网络路径规则
## 输入项：
##     $1--IPv4网址/网段地址列表全路径文件名
##     $2--路由表ID
##     $3--IP规则优先级
## 返回值：无
lz_add_dual_ip_rules() {
    if [ ! -f "${1}" ] || [ -z "${2}" ] || [ -z "${3}" ]; then return; fi;
    sed -e '/^[ \t]*[#]/d' -e 's/[#].*$//g' -e 's/[ \t][ \t]*/ /g' -e 's/^[ ]//' -e 's/[ ]$//' -e '/^[ ]*$/d' "${1}" 2> /dev/null \
        | awk '$1 ~ /^([0-9]{1,3}[\.]){3}[0-9]{1,3}([\/][0-9]{1,2}){0,1}$/ \
        && $1 !~ /[3-9][0-9][0-9]/ && $1 !~ /[2][6-9][0-9]/ && $1 !~ /[2][5][6-9]/ && $1 !~ /[\/][4-9][0-9]/ && $1 !~ /[\/][3][3-9]/ \
        && $1 != "0.0.0.0/0" \
        && NF >= "1" {
            system("ip rule add from "$1"'" table ${2} prio ${3} > /dev/null 2>&1; ip rule add from all to "'"$1"'" table ${2} prio ${3} > /dev/null 2>&1;"'")
        }'
}

## 获取IPv4网址/网段地址列表文件中的列表数据
## 输入项：
##     $1--IPv4网址/网段地址列表全路径文件名
## 返回值：
##     数据列表
lz_get_ipv4_list_from_data_file() {
    local retval=""
    [ -f "${1}" ] && {
        retval="$( sed -e '/^[ \t]*[#]/d' -e 's/[#].*$//g' -e 's/[ \t][ \t]*/ /g' -e 's/^[ ]//' -e 's/[ ]$//' -e '/^[ ]*$/d' "${1}" 2> /dev/null \
            | awk '$1 ~ /^([0-9]{1,3}[\.]){3}[0-9]{1,3}([\/][0-9]{1,2}){0,1}$/ \
            && $1 !~ /[3-9][0-9][0-9]/ && $1 !~ /[2][6-9][0-9]/ && $1 !~ /[2][5][6-9]/ && $1 !~ /[\/][4-9][0-9]/ && $1 !~ /[\/][3][3-9]/ \
            && $1 != "0.0.0.0/0" \
            && NF >= "1" {print $1}' )"
    }
    echo "${retval}"
}

## 添加从源地址到目标地址列表访问网络路径规则
## 输入项：
##     $1--IPv4源网址/网段地址
##     $2--IPv4目标网址/网段地址列表全路径文件名
##     $3--路由表ID
##     $4--IP规则优先级
## 返回值：无
lz_add_src_to_dst_sets_ip_rules() {
    if [ -z "${1}" ] || [ ! -f "${2}" ] || [ -z "${3}" ] || [ -z "${4}" ]; then return; fi;
    [ "${1}" = "0.0.0.0/0" ] && return
    sed -e '/^[ \t]*[#]/d' -e 's/[#].*$//g' -e 's/[ \t][ \t]*/ /g' -e 's/^[ ]//' -e 's/[ ]$//' -e '/^[ ]*$/d' "${2}" 2> /dev/null \
        | awk '$1 ~ /^([0-9]{1,3}[\.]){3}[0-9]{1,3}([\/][0-9]{1,2}){0,1}$/ \
        && $1 !~ /[3-9][0-9][0-9]/ && $1 !~ /[2][6-9][0-9]/ && $1 !~ /[2][5][6-9]/ && $1 !~ /[\/][4-9][0-9]/ && $1 !~ /[\/][3][3-9]/ \
        && $1 != "0.0.0.0/0" \
        && NF >= "1" {system("'"ip rule add from ${1} to "'"$1"'" table ${3} prio ${4} > /dev/null 2>&1"'")}'
}

## 添加从源地址列表到目标地址访问网络路径规则
## 输入项：
##     $1--IPv4源网址/网段地址列表全路径文件名
##     $2--IPv4目标网址/网段地址
##     $3--路由表ID
##     $4--IP规则优先级
## 返回值：无
lz_add_src_sets_to_dst_ip_rules() {
    if [ ! -f "${1}" ] || [ -z "${2}" ] || [ -z "${3}" ] || [ -z "${4}" ]; then return; fi;
    [ "${2}" = "0.0.0.0/0" ] && return
    sed -e '/^[ \t]*[#]/d' -e 's/[#].*$//g' -e 's/[ \t][ \t]*/ /g' -e 's/^[ ]//' -e 's/[ ]$//' -e '/^[ ]*$/d' "${1}" 2> /dev/null \
        | awk '$1 ~ /^([0-9]{1,3}[\.]){3}[0-9]{1,3}([\/][0-9]{1,2}){0,1}$/ \
        && $1 !~ /[3-9][0-9][0-9]/ && $1 !~ /[2][6-9][0-9]/ && $1 !~ /[2][5][6-9]/ && $1 !~ /[\/][4-9][0-9]/ && $1 !~ /[\/][3][3-9]/ \
        && $1 != "0.0.0.0/0" \
        && NF >= "1" {system("ip rule add from "$1"'" to ${2} table ${3} prio ${4} > /dev/null 2>&1"'")}'
}

## 调整和更新igmpproxy参数
## 输入项：
##     $1--IPTV线路在路由器内的接口设备ID（vlanx，pppx，ethx；x--数字编号）
##     全局变量
## 返回值：无
lz_djust_igmpproxy_parameters() {
    ## 校验输入项参数是否在取值范围内，否则退出
    ! echo "${1}" | grep -qE 'vlan[0-9]*|eth[0-9]*|ppp[0-9]*' && return
    ## 获取igmpproxy进程信息
    local igmp_filename="$( ps | awk '!/awk/ && /igmpproxy/ && /\.conf/ {print $6; exit}' )"
    if [ -n "${igmp_filename}" ]; then
        if [ -f "${igmp_filename}" ]; then
            ## 判断接口是否符合当前脚本参数设置
            if ! grep "phyint" "${igmp_filename}" | grep "upstream" | grep -q "${1}"; then
                ## 不符合则需杀掉当前进程
                killall "igmpproxy" > /dev/null 2>&1
                ## 生成IGMP代理配置文件
                ## 输入项：
                ##     $1--文件路径
                ##     $2--IGMP代理配置文件名
                ##     $3--IPTV线路在路由器内的接口设备ID
                ## 返回值：
                ##     0--成功
                ##     1--失败
                lz_create_igmp_proxy_conf "${PATH_TMP}" "igmpproxy.conf" "${1}"
                sleep "1s"
                ## 重新启动igmpproxy代理
                /usr/sbin/igmpproxy "${PATH_TMP}/igmpproxy.conf" > /dev/null 2>&1
                ## 再次获取igmpproxy进程信息
                igmp_filename="$( ps | awk '!/awk/ && /igmpproxy/ && /\.conf/ {print $6; exit}' )"
                if [ -n "${igmp_filename}" ]; then
                    echo "$(lzdate)" [$$]: IGMPPROXY service \( "${1}" \) is running. | tee -ai "${SYSLOG}" 2> /dev/null
                fi
            else
                echo "$(lzdate)" [$$]: IGMPPROXY service \( "${1}" \) is running. | tee -ai "${SYSLOG}" 2> /dev/null
            fi
        fi
    else
        ## hnd/axhnd/axhnd.675x平台机型无igmpproxy进程
        ## 设置hnd/axhnd/axhnd.675x平台核心网桥IGMP接口
        ## 输入项：
        ##     $1--接口标识
        ##     $2--0：IGMP&MLD；1：IGMP；2：MLD
        ##     $3--0：disabled；1：standard；2：blocking
        ## 返回值：
        ##     0--成功
        ##     1--失败
        lz_set_hnd_bcmmcast_if "br0" "0" "${hnd_br0_bcmmcast_mode}"
    fi
}

## ipv4网络掩码转换至掩码位
## 输入项：
##     $1--ipv4网络地址掩码
## 返回值：
##     0~32--ipv4网络地址掩码位数
lz_netmask2cdr() {
    local x="${1##*255.}"
    set -- "0^^^128^192^224^240^248^252^254^" "$(( (${#1} - ${#x})*2 ))" "${x%%.*}"
    x="${1%%"${3}"*}"
    echo "$(( ${2} + (${#x}/4) ))"
}

___main() {
    ## 处理系统负载均衡分流策略规则
    ## 输入项：
    ##     $1--规则优先级（150--ASUS原始；$(( IP_RULE_PRIO + 1 ))--脚本原定义）
    ##     全局常量
    ## 返回值：无
    lz_sys_load_balance_control "$(( IP_RULE_PRIO + 1 ))"

    ## 清除系统策略路由库中已有IPTV规则
    lz_del_iptv_rule

    ## 清空系统中已有IPTV路由表
    lz_clear_iptv_route

    ## 恢复系统原有IPTV服务
    ## 输入项：
    ##     $1--是否显示执行结果（1--显示；其它符号--禁止显示）
    ## 返回值：无
    local show_result="${STOP_RUN}"
    [ "${HAMMER}" = "${show_result}" ] && show_result="1"
    lz_restore_sys_iptv_services "${show_result}"

    ## 判断是否停止脚本提供的IPTV服务
    if [ "${HAMMER}" = "${STOP_RUN}" ]; then
        ## 清除firewall-start中脚本引导项
        lz_clear_firewall_start_command

        ## 恢复系统负载均衡分流策略规则为系统初始的优先级状态
        ## 处理系统负载均衡分流策略规则
        ## 输入项：
        ##     $1--规则优先级（150--ASUS原始；$(( IP_RULE_PRIO + 1 ))--脚本原定义）
        ##     全局常量
        ## 返回值：无
        lz_sys_load_balance_control "150"

        ## 停止服务并退出
        echo "$(lzdate)" [$$]: "LZ IPTV service support provided by the script has finished." | tee -ai "${SYSLOG}" 2> /dev/null
        return
    fi

    if [ -f "${PATH_BOOTLOADER}/${BOOTLOADER_NAME}" ] && grep -q "^[^#]*lz_rule[\.]sh" "${PATH_BOOTLOADER}/${BOOTLOADER_NAME}"; then
        ## 清除firewall-start中脚本引导项
        lz_clear_firewall_start_command
        echo "$(lzdate)" [$$]: "Please uninstall the lz_rule project before running it." | tee -ai "${SYSLOG}" 2> /dev/null
        return
    fi

    ## 创建firewall-start启动文件并添加脚本引导项
    lz_create_firewall_start_command

    ## 校验互联网接入路由器WAN口设定参数，错误则退出
    if [ "${internet_wan}" != "1" ] && [ "${internet_wan}" != "2" ]; then
        echo "$(lzdate)" [$$]: "internet_wan parameter error !!!" | tee -ai "${SYSLOG}" 2> /dev/null
        return
    fi

    ## 校验IPTV路由器WAN口设定参数，错误则退出
    if [ "${iptv_wan}" != "1" ] && [ "${iptv_wan}" != "2" ]; then
        echo "$(lzdate)" [$$]: "iptv_wan parameter error !!!" | tee -ai "${SYSLOG}" 2> /dev/null
        return
    fi

    ## 校验IPTV连接方式，错误则退出
    if [ "${iptv_get_ip_mode}" != "1" ] && [ "${iptv_get_ip_mode}" != "2" ] && [ "${iptv_get_ip_mode}" != "3" ]; then
        echo "$(lzdate)" [$$]: "iptv_get_ip_mode parameter error !!!" | tee -ai "${SYSLOG}" 2> /dev/null
        return
    fi

    ## 校验IPTV机顶盒访问IPTV网络方式，错误则退出
    if [ "${iptv_access_mode}" != "1" ] && [ "${iptv_access_mode}" != "2" ]; then
        echo "$(lzdate)" [$$]: "iptv_access_mode parameter error !!!" | tee -ai "${SYSLOG}" 2> /dev/null
        return
    fi

    ## 校验hnd平台机型核心网桥组播控制方式，错误则退出
    if [ "${hnd_br0_bcmmcast_mode}" != "0" ] && [ "${hnd_br0_bcmmcast_mode}" != "1" ] && [ "${hnd_br0_bcmmcast_mode}" != "2" ]; then
        echo "$(lzdate)" [$$]: "hnd_br0_bcmmcast_mode parameter error !!!" | tee -ai "${SYSLOG}" 2> /dev/null
        return
    fi

    ## 路由器内网网段
    if ! ip -o -4 addr list | awk '/br0/ {print $4; exit}' | grep -qE '([0-9]{1,3}[\.]){3}[0-9]{1,3}([\/][0-9]{1,2}){0,1}'; then
        echo "$(lzdate)" [$$]: "Unable to get to the router network segment data !!!" | tee -ai "${SYSLOG}" 2> /dev/null
        return
    fi

    ## IPTV网关地址
    iptv_getway_ip=""

    ## IPTV线路在路由器内的接口设备ID（vlanx，pppx，ethx；x--数字编号）
    iptv_interface_id=""

    ## 从系统中获取接口ID标识
    iptv_wan0_ifname="$( nvram get "wan0_ifname" | grep -Eo 'vlan[0-9]*|eth[0-9]*' | sed -n 1p )"
    iptv_wan1_ifname="$( nvram get "wan1_ifname" | grep -Eo 'vlan[0-9]*|eth[0-9]*' | sed -n 1p )"

    ## 从系统中获取光猫网关地址
    iptv_wan0_xgateway="$( nvram get "wan0_xgateway" | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | sed -n 1p )"
    iptv_wan1_xgateway="$( nvram get "wan1_xgateway" | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | sed -n 1p )"

    ## 判断路由器是否采用双线路双WAN口接入，获取IPTV线路在路由器内的接口设备ID和IPTV网关地址
    iptv_wan_id="${WAN0}"
    iptv_interface_id="${iptv_wan0_ifname}"
    iptv_getway_ip="${iptv_wan0_xgateway}"
    if [ "${iptv_wan}" = "2" ]; then
        iptv_wan_id="${WAN1}"
        iptv_interface_id="${iptv_wan1_ifname}"
        iptv_getway_ip="${iptv_wan1_xgateway}"
    fi
    if ip route show | grep -q nexthop; then
        if [ "${iptv_get_ip_mode}" = "3" ]; then
            iptv_interface_id="$( ip route show table "${iptv_wan_id}" | grep "default" | grep -Eo 'ppp[0-9]*' | sed -n 1p )"
            iptv_getway_ip="$( ip route show table "${iptv_wan_id}" | awk '/default/ && $0 ~ "'"${iptv_interface_id}"'" {print $3}' | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | sed -n 1p )"
            if [ -z "${iptv_interface_id}" ] || [ -z "${iptv_getway_ip}" ]; then
                iptv_interface_id="${iptv_wan0_ifname}"
                iptv_getway_ip="${iptv_wan0_xgateway}"
                if [ "${iptv_wan}" = "2" ]; then
                    iptv_interface_id="${iptv_wan1_ifname}"
                    iptv_getway_ip="${iptv_wan1_xgateway}"
                fi
            fi
        fi
    else
        ## 单线接入
        if [ "${iptv_get_ip_mode}" = "3" ]; then
            iptv_interface_id="$( ip route show | grep default | grep -Eo 'ppp[0-9]*' | sed -n 1p )"
            iptv_getway_ip="$( ip route show | awk '/default/ && $0 ~ "'"${iptv_interface_id}"'" {print $3}' | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | sed -n 1p )"
            if [ -z "${iptv_interface_id}" ] || [ -z "${iptv_getway_ip}" ]; then
                iptv_interface_id="${iptv_wan0_ifname}"
                iptv_getway_ip="${iptv_wan0_xgateway}"
                if [ "${iptv_wan}" = "2" ]; then
                    iptv_interface_id="${iptv_wan1_ifname}"
                    iptv_getway_ip="${iptv_wan1_xgateway}"
                fi
            fi
        fi
        if [ -z "${iptv_interface_id}" ] || [ -z "${iptv_getway_ip}" ]; then
            iptv_interface_id="${iptv_wan1_ifname}"
            iptv_getway_ip="${iptv_wan1_xgateway}"
            if [ "${iptv_wan}" = "2" ]; then
                iptv_interface_id="${iptv_wan0_ifname}"
                iptv_getway_ip="${iptv_wan0_xgateway}"
            fi
        fi
    fi

    ## 如果在路由器内无法获取到IPTV线路的接口设备ID，则退出
    if [ -z "${iptv_interface_id}" ]; then
        echo "$(lzdate)" [$$]: "Unable to get interface device ID of IPTV line in router !!!" | tee -ai "${SYSLOG}" 2> /dev/null
        return
    fi

    ## 如果在路由器内无法获取到IPTV线路的网关地址，则退出
    if [ -z "${iptv_getway_ip}" ]; then
        echo "$(lzdate)" [$$]: "Unable to get gateway address of IPTV line in router !!!" | tee -ai "${SYSLOG}" 2> /dev/null
        return
    fi

    ## 光猫内网网段
    if [ "${iptv_get_ip_mode}" != "3" ] && ! ip -o -4 addr list | awk '$0 ~ "'"${iptv_interface_id}"'" {print $4; exit}' | grep -qE '([0-9]{1,3}[\.]){3}[0-9]{1,3}([\/][0-9]{1,2}){0,1}'; then
        echo "$(lzdate)" [$$]: "Unable to get the local network segment of optical modem !!!" | tee -ai "${SYSLOG}" 2> /dev/null
        return
    fi

    ## 向系统策略路由库中添加双向访问网络路径规则
    ## 输入项：
    ##     $1--IPv4网址/网段地址列表全路径文件名
    ##     $2--路由表ID
    ##     $3--IP规则优先级
    ## 返回值：无
    if [ "${iptv_access_mode}" = "1" ]; then
        if [ -f "/tmp/lz_iptv_box_ip.lst" ]; then
            lz_add_dual_ip_rules "/tmp/lz_iptv_box_ip.lst" "${LZ_IPTV}" "${IP_RULE_PRIO_IPTV}"
        fi
    else
        if [ -f "/tmp/lz_iptv_box_ip.lst" ] && [ -f "/tmp/lz_iptv_ip_addr.lst" ]; then
            local ip_list_item=""
            ## 获取IPv4网址/网段地址列表文件中的列表数据
            ## 输入项：
            ##     $1--IPv4网址/网段地址列表全路径文件名
            ## 返回值：
            ##     数据列表
            for ip_list_item in $( lz_get_ipv4_list_from_data_file "/tmp/lz_iptv_box_ip.lst" )
            do
                ## 添加从源地址到目标地址列表访问网络路径规则
                ## 输入项：
                ##     $1--IPv4源网址/网段地址
                ##     $2--IPv4目标网址/网段地址列表全路径文件名
                ##     $3--路由表ID
                ##     $4--IP规则优先级
                ## 返回值：无
                lz_add_src_to_dst_sets_ip_rules "${ip_list_item}" "/tmp/lz_iptv_ip_addr.lst" "${LZ_IPTV}" "${IP_RULE_PRIO_IPTV}"
            done
            ## 获取IPv4网址/网段地址列表文件中的列表数据
            ## 输入项：
            ##     $1--IPv4网址/网段地址列表全路径文件名
            ## 返回值：
            ##     数据列表
            for ip_list_item in $( lz_get_ipv4_list_from_data_file "/tmp/lz_iptv_box_ip.lst" )
            do
                ## 添加从源地址列表到目标地址访问网络路径规则
                ## 输入项：
                ##     $1--IPv4源网址/网段地址列表全路径文件名
                ##     $2--IPv4目标网址/网段地址
                ##     $3--路由表ID
                ##     $4--IP规则优先级
                ## 返回值：无
                lz_add_src_sets_to_dst_ip_rules "/tmp/lz_iptv_ip_addr.lst" "${ip_list_item}" "${LZ_IPTV}" "${IP_RULE_PRIO_IPTV}"
            done
        fi
    fi

    ## 向IPTV路由表中添加路由项
    ip route show | awk '!/default|nexthop/ && NF!=0 {system("ip route add "$0"'" table ${LZ_IPTV} > /dev/null 2>&1"'")}'
    ip route add default via "${iptv_getway_ip}" dev "${iptv_interface_id}" table "${LZ_IPTV}" > /dev/null 2>&1

    ## 刷新路由器路由表缓存
    ip route flush cache > /dev/null 2>&1

    ## 判断是否已接入指定的IPTV接口设备
    if ip route show table "${LZ_IPTV}" | grep -q "default"; then
        if [ "$( ip rule show | grep -c "^${IP_RULE_PRIO_IPTV}:" )" -gt "0" ]; then
            ## 调整和更新igmpproxy参数
            ## 输入项：
            ##     $1--IPTV线路在路由器内的接口设备ID（vlanx，pppx，ethx；x--数字编号）
            ##     全局变量
            ## 返回值：无
            lz_djust_igmpproxy_parameters "${iptv_interface_id}"
        else
            ## 清除系统策略路由库中已有IPTV规则
            lz_del_iptv_rule

            ## 清空系统中已有IPTV路由表
            lz_clear_iptv_route

            ## 刷新路由器路由表缓存
            ip route flush cache > /dev/null 2>&1
        fi

        ## 调整和更新udpxy参数
        ## 输入项：
        ##     $1--IPTV线路在路由器内的接口设备ID（vlanx，pppx，ethx，nnn--未知接口；x--数字编号）
        ##     $2--是否显示执行结果（1--显示；其它符号--禁止显示）
        ## 返回值：无
        lz_djust_udpxy_parameters "${iptv_interface_id}" "1"

        if ip route show table "${LZ_IPTV}" | grep -q "default" && [ "$( ip rule show | grep -c "^${IP_RULE_PRIO_IPTV}:" )" -gt "0" ]; then
            if ip route show | grep -q nexthop; then
                local route_local_ip="$( /sbin/ifconfig "br0" | awk 'NR==2 {print $2}' | awk -F: '{print $2}' )"
                local route_local_ip_mask="$( /sbin/ifconfig "br0" | awk 'NR==2 {print $4}' | awk -F: '{print $2}' )"
                route_local_ip_mask="$( echo "${route_local_ip_mask}" | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" )"
                local local_ipv4_cidr_mask="$( lz_netmask2cdr "${route_local_ip_mask}" )"
                local internet_wan_id="${WAN0}"
                [ "${internet_wan}" != "1" ] && internet_wan_id="${WAN1}"
                ip rule add from all to "${route_local_ip}" table "${internet_wan_id}" prio "$(( IP_RULE_PRIO - 1 ))" > /dev/null 2>&1
                ip rule add from "${route_local_ip}" table "${internet_wan_id}" prio "$(( IP_RULE_PRIO - 1 ))" > /dev/null 2>&1
                ip rule add from all table "${internet_wan_id}" prio "${IP_RULE_PRIO}" > /dev/null 2>&1
                if iptables -t mangle -L PREROUTING 2> /dev/null | grep -q "balance"; then
                    ipset -q create "${BALANCE_IP_SET}" hash:net #--hashsize 1024 mexleme 65536
                    ipset -q flush "${BALANCE_IP_SET}"
                    ipset -q add "${BALANCE_IP_SET}" "${route_local_ip%.*}.0/${local_ipv4_cidr_mask}"
                    get_match_set
                    eval "iptables -t mangle -I balance -m set ${MATCH_SET} ${BALANCE_IP_SET} src -j RETURN > /dev/null 2>&1"
                    ipset -q destroy "${BALANCE_IP_SET}"
                fi
            fi
            echo "$(lzdate)" [$$]: "IPTV STB can be connected to ${iptv_interface_id} interface for use." | tee -ai "${SYSLOG}" 2> /dev/null
        fi
    else
        ## 清除系统策略路由库中已有IPTV规则
        lz_del_iptv_rule

        ## 清空系统中已有IPTV路由表
        lz_clear_iptv_route

        ## 刷新路由器路由表缓存
        ip route flush cache > /dev/null 2>&1

        echo "$(lzdate)" [$$]: "Connection ${iptv_interface_id} IPTV interface failure !!!" | tee -ai "${SYSLOG}" 2> /dev/null
    fi
}

{
    echo "$(lzdate)" [$$]:
    echo "$(lzdate)" [$$]: LZ IPTV "${LZ_VERSION}" script commands start......
    echo "$(lzdate)" [$$]: By LZ \(larsonzhang@gmail.com\)
    if [ "${HAMMER}" = "${STOP_RUN}" ]; then
        echo "$(lzdate)" [$$]: "Stop the IPTV service......"
    elif [ "${HAMMER}" = "${FORCED_UNLOCKING}" ]; then
        echo "$(lzdate)" [$$]: "Unlock the IPTV service......"
    else
        echo "$(lzdate)" [$$]: "Start the IPTV service......"
    fi
} | tee -ai "${SYSLOG}" 2> /dev/null

while true
do
    set_lock || break
    ___main
    break
done

## 清除IPTV机顶盒内网IP地址列表临时文件
if [ -f /tmp/lz_iptv_box_ip.lst ]; then
    rm -f "/tmp/lz_iptv_box_ip.lst" > /dev/null 2>&1
fi

## 清除IPTV网络服务IP网址/网段列表临时文件
if [ -f /tmp/lz_iptv_ip_addr.lst ]; then
    rm -f "/tmp/lz_iptv_ip_addr.lst" > /dev/null 2>&1
fi

## 解除文件同步锁
unset_lock

{
    echo "$(lzdate)" [$$]: LZ IPTV "${LZ_VERSION}" script commands executed!
    echo "$(lzdate)" [$$]:
} | tee -ai "${SYSLOG}" 2> /dev/null

# END
