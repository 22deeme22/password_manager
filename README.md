# Passmngr

Passmngr is a CLI password manager in Rust, that use ChaCha20Poly1305 for encryption.

## Installation

First, make sure that you have Rust installed.
Then use cargo to install pssmngr.

```bash
cargo install --git https://github.com/22deeme22/passmngr
```
After this, go to your <ins>"~/.bashrc"</ins> (or <ins>"~/.zshrc"</ins> if you use zsh) file, and at the end of the file, paste
```
export PATH="$HOME/.cargo/bin:$PATH"
```
It's ready to use! :shipit:

## Usage

To use the password manager, you have to write **passmngr** followed by one of this command:
- **add**: With this command, you add an entry to your password manager file, you have to specify the service, your login and your password.

Use:
```
passmngr add -s github -l 22deeme22 -p 12345678
```
- **remove**: With this command, you remove an entry of your password manager, you have to specify the service.

Use:
```
passmngr remove github
```
- **list**: With this command, you list every entry that is in your password manager.

Use:
```
passmngr list
```
- **info**: With this command, you get the login and the password of the service specified.

Use:
```
passmngr info github
```
- **passwd**: With this command, you can change the password that you chose for your password manager.

Use:
```
passmngr passwd
```
Notice that you can see every information by just write **passmngr** in your terminal! :flushed: :face_holding_back_tears: :partying_face:

## Contribution
Pull requests are welcome. For major changes, please open an issue to discuss what you would like to change.
