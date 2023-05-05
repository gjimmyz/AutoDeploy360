cat case_for_init.sh

#!/bin/bash
if [[ `id -u` -eq 0 ]]
then
    while true
    do
        echo -e "
        \033[31m 1|a|A 迷你PC Intel NUC业务部署 \033[0m
        \033[32m 2|b|B 进入管理系统 \033[0m
        \033[33m 99|q|Q 退出 \033[0m
        "
        read -p "请选择主菜单选项: " main_menu_choice
        case $main_menu_choice in
            1|a|A)
                while true
                do
                    echo -e "
                    \033[31m 1|a|A 部署软件&&重启机器 \033[0m
                    \033[32m 2|b|B 检查 \033[0m
                    \033[33m 3|c|C 返回主菜单 \033[0m
                    \033[34m 99|q|Q 退出 \033[0m
                    "
                    read -p "请选择二级菜单选项: " submenu_choice
                    case $submenu_choice in
                        1|a|A)
                            cd /root/scripts/ansible_yaml && `which ansible-playbook` sh_connect_for_US2004.yaml
                            cd /root/scripts/ansible_yaml && `which ansible-playbook` -i hosts.yaml init_for_US2004.yaml
                            ;;
                        2|b|B)
                            ls -l
                            ;;
                        3|c|C)
                            break
                            ;;
                        99|q|Q)
                            exit 0
                            ;;
                        *)
                            echo "再多一次机会给你～"
                            ;;
                    esac
                done
                ;;
            2|b|B)
                bash
                ;;
            99|q|Q)
                exit 0
                ;;
            *)
                echo "再多一次机会给你～"
                ;;
        esac
    done
fi