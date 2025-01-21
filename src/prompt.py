import os
from openai import OpenAI
import pymysql

def generate_prompt(input_data):
    prompt = f"""
Instruction:
Map a sequence of operations from the .bash_history to the relevant attack tactics based on the ATT&CK framework.

Context:
The .bash_history records user activities in the terminal, and a series of closely related logs may indicate potential attack behavior. For example, a sequence involving downloading, compiling, and executing files may suggest a privilege escalation attempt by the attacker.
The ATT&CK framework divides the complete attack  lifecycle into 14 stages, including Reconnaissance, Resource_Development, Initial_Access, Execution, Persistence, Privilege_Escalation, Defense_Evasion, Credential_Access, Discovery, Lateral_Movement, Collection, Command_and_Control, Exfiltration, and Impact.

Input:
The input is a list with each item representing a single operation in the .bash_history.

Example:
1. ["wget http://.../LinEnum.sh", "vim LinEnum.sh", "chmod +x LinEnum.sh", "bash LinEnum.sh"]
output: Collection
2. ["sudo python3 dirsearch.py -u http://10.0.0.11/ -w dict.txt > result.txt", "cat result.txt"]
output: Discovery

Output Indicator:
You should only return the corresponding attack tactics, including Reconnaissance, Resource_Development, Initial_Access, Execution, Persistence, Privilege_Escalation, Defense_Evasion, Credential_Access, Discovery, Lateral_Movement, Collection, Command_and_Control, Exfiltration, and Impact. Please keep the underscores.
However, if you think the sequence of operations do not belong to any attack tactics, please return "invalid". please do not generate any other irrelevant information.

Now please analyze the semantics of the sequence of operations in the .bash_history and identify the corresponding attack tactics.
Log entry: {input_data}
"""
    return prompt


def get_behavior_stage(input_data):
    client = OpenAI(
        api_key=os.getenv("DASHSCOPE_API_KEY"), 
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )
    completion = client.chat.completions.create(
        model="qwen-turbo", # Available Model List：https://help.aliyun.com/zh/model-studio/getting-started/models
        messages=[
            {'role': 'system', 'content': 'You are a log analysis assistant, specialized in processing and correlating multi-source logs. You should response in English.'},
            {'role': 'user', 'content': generate_prompt(input_data)}],
        seed=0,
        )
        
    return completion.choices[0].message.content