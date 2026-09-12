import os,json,base64,getpass,hashlib,secrets
from pathlib import Path
try:
 from cryptography.fernet import Fernet,InvalidToken
except ImportError:
 print('Missing dependency. Run: pip install cryptography'); raise SystemExit(1)
BASE=Path(__file__).resolve().parent; DATA=BASE/'data'; VAULT=DATA/'vault.enc'; CONFIG=DATA/'config.json'; LOG=BASE/'logs'/'vault.log'
def log(s): LOG.parent.mkdir(exist_ok=True); open(LOG,'a',encoding='utf-8').write(s+'\n')
def key_from(pw,salt): return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,600000,32))
def auth():
 if not CONFIG.exists():
  print('\n=== Create New Vault ==='); p=getpass.getpass('Create master password: '); q=getpass.getpass('Confirm master password: ')
  if not p or p!=q: print('Invalid or mismatched password.'); return None
  salt=secrets.token_bytes(16); k=key_from(p,salt); CONFIG.write_text(json.dumps({'salt':base64.b64encode(salt).decode(),'verifier':hashlib.sha256(k).hexdigest()},indent=2)); DATA.mkdir(exist_ok=True); VAULT.write_bytes(Fernet(k).encrypt(b'[]')); print('Vault created successfully.'); log('Vault created'); return k
 c=json.loads(CONFIG.read_text()); p=getpass.getpass('Master password: '); k=key_from(p,base64.b64decode(c['salt']))
 if not secrets.compare_digest(hashlib.sha256(k).hexdigest(),c['verifier']): print('Authentication failed.'); log('Failed authentication attempt'); return None
 print('Authentication successful.'); log('Successful authentication'); return k
def load(k):
 try:return json.loads(Fernet(k).decrypt(VAULT.read_bytes()))
 except (InvalidToken,ValueError,json.JSONDecodeError): print('Unable to decrypt vault.'); return []
def save(k,e): VAULT.write_bytes(Fernet(k).encrypt(json.dumps(e,indent=2).encode()))
def add(k):
 e=load(k); title=input('Account/title: ').strip(); user=input('Username/email: ').strip(); pw=getpass.getpass('Password/secret: '); notes=input('Notes (optional): ').strip()
 if not title or not pw: print('Title and password are required.'); return
 e.append({'title':title,'username':user,'password':pw,'notes':notes}); save(k,e); print('Entry saved securely.'); log('Entry added: '+title)
def view(k):
 e=load(k)
 if not e: print('Vault is empty.'); return
 for i,x in enumerate(e,1): print(f"\n[{i}] {x['title']}\nUsername : {x['username']}\nPassword : {x['password']}\nNotes    : {x['notes']}")
def search(k):
 e=load(k); q=input('Search title/username: ').lower(); m=[x for x in e if q in x['title'].lower() or q in x['username'].lower()]
 if not m: print('No matching entries.'); return
 for x in m: print(f"\n{x['title']} | {x['username']} | {x['password']} | {x['notes']}")
def delete(k):
 e=load(k)
 if not e: print('Vault is empty.'); return
 for i,x in enumerate(e,1): print(f'{i}. {x["title"]} ({x["username"]})')
 try:n=int(input('Entry number to delete: ')); x=e.pop(n-1)
 except (ValueError,IndexError): print('Invalid entry number.'); return
 save(k,e); print('Entry deleted.'); log('Entry deleted: '+x['title'])
def main():
 print('='*45+'\n     SECURE NOTES / PASSWORD VAULT\n'+'='*45); k=auth()
 if not k:return
 while True:
  print('\n1. Add Password / Secret\n2. View Passwords\n3. Search\n4. Delete Password\n5. Exit'); c=input('\nEnter choice: ')
  if c=='1':add(k)
  elif c=='2':view(k)
  elif c=='3':search(k)
  elif c=='4':delete(k)
  elif c=='5':print('Vault locked. Goodbye.'); break
  else:print('Invalid choice.')
if __name__=='__main__':main()
