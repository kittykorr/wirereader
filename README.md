# wirereader
The intent of this project was to develop a PYTHON CLI program to parse Wireshark outputs and resolve Human Readable Logs from packet information. 

WIP

It didn't quite decode payload what I intended, but the results are still fun.

Simply download and unzip the package.

Be sure to change your filepath to the correct output folder of your Wireshark or other packet sniffer logs inside of 'wirereader.py'.

If everything is correct, click 'run.bat' inside of root folder.

The program should run automatically and output a nice log.

After running the WireReader.py, navigate to the 'paylode_decode' folder and run the .bat.

This part will parse your Human Readable Log and attempt to decode the payload.

It has not been successful, but with a little tweaking I hope to see it implemented as a decryption tool for more than just packet data.
