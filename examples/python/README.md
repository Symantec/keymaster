
# generate self signed cert
```
# your website that keymaster will accept local.<yourwebsite>
export WEBSITE=example.com
cd ./selfsign
docker build -t selfsign .
docker run -e "WEBSITE=$WEBSITE" -v `pwd`/output:/output selfsign
```

# redirect localhost.<yourwebsite> to 127.0.0.1
sudo bash -c "echo '127.0.0.1  localhost.$WEBSITE' >> /etc/hosts"


# run python server
```
# sudo because we're binding 443
pip3 install -r requirements.txt
sudo python3 app.py
```
