# burp_macro

test

2022-04/06 11:12

burpモジュールやjava.langモジュールなどは、
Jython指定して実行するだけでOK。
（他に設定はしていないけど、実行できる）

作成したPythonを読み込ませる際は、
ファイルパスに日本語が入っていないフォルダで読み込ませるようにする。
（日本語がファイルパスに入っていると、エラーになる）


2022-07/01 17:05

■Burp開発環境の備忘録

・ソースコードは、VScode上で書く
・全角・日本語は使わない。（日本語書いてあると、Burp上で読込時にエラーになる）
・デバッグは、Burp上で行う（Burp -> Extender -> 拡張）
　ロードし直す度に、実行するので、手間はほとんどない。
　（ただ、デバッガーを使うには一工夫がいる。）

↓あたりのライブラリの読込が、単独で実行した際は用意しにくいから、Burp上でデバッグする。
from burp import IBurpExtender
from java.io import PrintWriter
from java.lang import RuntimeException


2022-07/01 17:22
◎BappStoreのソースコード見れた！　

1. https://portswigger.net/bappstore から参考になりそうなBappファイルをダウンロード
2. zipで展開
3. 2で展開したPythonをBurpにLoadもできるし、ソースも見れる。
  
