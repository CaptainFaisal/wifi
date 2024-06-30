import argparse
parser = argparse.ArgumentParser(description='Test program')
parser.add_argument('-p', '--password', help='A password', default="password")
args = parser.parse_args()
if(args.password):
    print(f"Password: {args.password}")
else:
    print("No password provided")