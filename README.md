<img width="782" height="503" alt="image" src="https://github.com/user-attachments/assets/f0f1e525-7b8a-48c7-ae01-0f0574e03727" />

The TCP-mode and SYN-mode(need sudo) are added.

# Ping-mode (default)
python3 HAS.py -i targets.txt

# TCP-mode
python3 HAS.py -i targets.txt -m tcp -p 80,443,8000-9000

# SYN-mode (need root prive)
sudo python3 HAS.py -i targets.txt -m syn -p 22,80,443

input file format (targets.txt):
192.168.1.1
example.com
10.0.0.5:8080
example.com:443