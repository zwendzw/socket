#!/bin/bash
output=$( find . -maxdepth 1 -type f -name Makefile -execdir make $input \; )
echo "$output"
read -e -p 'Would you like to continue?[y/n]' stdin 
until [ "$IsQuit" = "YES" ]
do
    if [[ $stdin =~ ^(y|Y)$ ]]
    then
        read -e -p '
    +-----------------------------------+
    |  - Use create_key_pair :       1  |
    |  - Use create_csr :            2  |
    |  - Use create_certificate  :   3  |
    |  - Leave :                     0  |
    +-----------------------------------+

continue?

' selection
echo -e "\n"
        case "$selection" in
            1) echo "--------------------"; ./create_key_pair;      echo "--------------------";;
            2) echo "--------------------"; ./create_csr;           echo "--------------------";;
            3) echo "--------------------"; ./create_certificate;   echo "--------------------";;
            0) echo -e "Leaving.\n"; echo "--------------------"; break;;
        esac
        continue
    elif [[ $stdin =~ ^(n|N)$ ]]
    then
        break
    fi
done
printf '\nexiting.\n'
exit
