package certgen

import (
	"crypto/sha256"
	"encoding/base64"
	"golang.org/x/crypto/ssh"
	//"strings"
	"os/user"
	"testing"
)

/*
func TestMissingGroup(t *testing.T) {

        val1 := strings.NewReader(user1Data)
        val2 := strings.NewReader(user1MissingEngineeringGroup)
        r, err := getDiff(val1, val2)
        if err != nil {
                t.Fatal(err)
        }
        if r == "" {
                t.Errorf("expecting data, got empty")
        }
        t.Log("got '%s'", r)

}
*/

const testSignerPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAv2J464KoYbODMIbtkTV58g6/0QTdUIYgOwnzPdaMNVtCOxTi
QDIWEbzqv1HEP9hfzuaSKHUHs/91e4Jj2qZghSwPHLG7TKzu+/CRK9sa9jvoGEVx
g6yjibPndTGuLVptZCcOIcHEXViP4iraI6dybiGDlmeF92WQJdI7l4Esg4W4Wp17
JFWNHbylKoFB0fe2b4q5pzaXMBwNue4BKKvua51NBctRy4LZYwiGvVJplEbjBU7v
wCAS0X4m72y2JvKog9/HfGKo2rZ9se0wFe9mMkjj0wuKkDh91pOzsBZ/0PW0zHci
2q9yJVxF0b41e9+raXa8kvRjxF7EEAuUr9Ov2wIDAQABAoIBAQCPmP4rjyRx8jQr
9AFKY7p00XZBCYpZAdorEiMtMc6PtkJyfA/qpOoEMyBbnqlGUj5Iyp29t1mpR7LJ
kiMECrP/F/jaycxEErlZ1b3HDyYivP4/P9OVPbKS/qZbO4R5yRCtBdTHpVCFzY5f
31E/UUM9uO23q0NMRisrBZvq6GQS5bPIbV/JHJIj1Xd65pZQKQMlRKdXnQGWANV6
4i6Yjcy8v/hqI4wxiwxGlAC26+d1Ow4sdHsMiRmA31vhJNMktdVfT3emyiIlLwoi
Oolbak9CpV2bvtN6iL0Hy4ek0TZp7QPzp7MT4Bhcf8jj9ykxL51SplJoOh2xVwfF
U4aaf1mJAoGBAPKP3an+LFPl8+Re8kVJay7JQrNOIzuoDsDbfhVQMJ9KuodGBz8U
YaUeK8iYZFRuYB/OuIqoDiFnlcdC441+M9VRMhuKwq1rLUOz92esyfiwn8CNzEnT
bJKDPvLocGtpRrN+2iqy+/ySk0IX7NUtsB2/8KXLXImY3ecTafjjqv4dAoGBAMn8
yM03RuBOTXsxWRjPIGBniH0mZG+7KdEbBGmhvhoZ8+uneXJvNL+0xswnf6S4r1tm
mEWM1PldE0tPbRID148Mm2H+tCv7IwtpXSRTKEb175Xkj+pIcFtBC1bkGdNv8DJW
BdkKVnDD2h6rND1IOHatBNjW+CO+2R3aZPUxBGRXAoGAfWu0QzTg+NS7QodxoC/x
UvTQH2S0xSEF1+TmkeCv832xa0bjclN4lec+3m8l2Z5k5619MHzrKYylHq5QeRYb
eR6N2T3rob38XriMobfviz7Qq8DmM/o1dqCUiQd1MaTy4NcjudZog1XK/O7gD+6a
1RctOJ0pkSBRBS29qusVvGUCgYEAtvsDRbUvxf/pfRKlbi4lXHAuW4GuNvHM3hul
kbPurWKZcAAVqy9HD+xKs6OMpMKSSTDV/RupzAUfd3gKjOliG7sGAG5m9fjaNHpM
4J1cvXwKgTW/kjPxZRm1lg+pvbuIU3FOduJAkIM8U9Aw0NteG1R+MZn8zRUVR1AT
aXPwUJ0CgYEA6Fpq8/MFJyzpcvlxkZSfZOVFmkDbE3+UYkB0WAR0X7sTdN74nrTf
RnmMXhcdJ7cCPL6LJpN82h62XrLVwl7zEBXnVfhSsXil1yYHHI5sGXbUFRzaNXNl
KgeanQGV/sG+nd/67uvHhZbifHVDY/ifsNBnYrlpu6q3p+zhQydfkLE=
-----END RSA PRIVATE KEY-----`

/*
const testSignerPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/Ynjrgqhhs4Mwhu2RNXnyDr/RBN1QhiA7CfM91ow1W0I7FOJAMhYRvOq/UcQ/2F/O5pIodQez/3V7gmPapmCFLA8csbtMrO778JEr2xr2O+gYRXGDrKOJs+d1Ma4tWm1kJw4hwcRdWI/iKtojp3JuIYOWZ4X3ZZAl0juXgSyDhbhanXskVY0dvKUqgUHR97ZvirmnNpcwHA257gEoq+5rnU0Fy1HLgtljCIa9UmmURuMFTu/AIBLRfibvbLYm8qiD38d8Yqjatn2x7TAV72YySOPTC4qQOH3Wk7OwFn/Q9bTMdyLar3IlXEXRvjV736tpdryS9GPEXsQQC5Sv06/b camilo_viecco1@localhost`

const testUserPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyNPX6TFk3mMO/xDv/hcsEv7IITV3U3k1sV+ytjde6MLECV/L
O+ixlSHVXmK1oOEEpmJaX+hFUgqcf32wms67BuxSVU0YRMcxW0U/WrJr80vr4l0m
0r52r4Ts/6WoocmjLFTylb9uLxejDrPA4H8HoXCgj4yqCD55WF2WmXMtOSjnGZrL
2LtpDTj+rEowxRfq7vk/gy6dw1BsPjD6+OSLke4g54V4ZJaslJ9He6LtKzh18/Rn
RyM6a/gwKEBpkw5KW0BKNOu0Y37uNOoGC/KVRQ9Re2rAo1N/ZZUAnFPxxsj8puX2
tvTbm8NHc2WVxmVFRWpcaNNmDDOz/SOmY3grLwIDAQABAoIBAFX0ZcsHOxb76uU8
yJtGK7UNm3arPaFalaKPRRw8YsDY67Lfb0r681bTHlHBid+Lr8PPAMNf1JuiswzW
LQp1RRNXfn3H+4UkhHl+D/mvuAhwDEvcdstofb/t8soQizaD6PUGfrWdM3mwcjfO
s9TiSc/NNst59ySEKMerdtPCui5mEiLP6P7YWXWlK4DrLbYsrUcichZWaLybTH7S
tOs6nhQlI4yDviAqwIcBa/d/a0BRY8Fngf4oLYetTI1y1GPQ+Hwzev4jJL52yWxH
YZgEeS4IB1y9D6FmuP/a9wIx1FJhMqGKxOYG4gI+lSIfhBJqll2jKQaTN1/YVDBU
bowg8LECgYEA/CXBEreAT3VP4XzFGFt2dMOL84zCSdFqrIElLSNBWW2t8JoSPB/W
J57CQaclV+ItQzBV/IL9G5TyHG7mTnRCmh/aPaxnVaiB4ONyzuADC87M7O5bGR3b
7M7o8nkoXBdbTPabgohuw2NNcKEPsgJfKVwW75GYpjMD1a8sKu6qx/0CgYEAy+Vb
adAoDycVE0X7t3U8dC6IUYXMAD6+Jd0RwcURYMV4LH2lFC9/VMY9z2i60MZPHhN7
odIXvWf21WarxZk5pHdg8giBtx2Ymyv3aIiWgW0MeoVRZhRnbuYAHwd4/dFBgSeZ
REvpz6LHgmBSErHyf3+XAqott5aaMUb4WbN8+ZsCgYEAmv0p/LNG75CQlW34SMyP
t54rfH1dP7q182s+yswM80dzz50k8EgxfxEbHvf7AFZKtC4V7K0nn7iiSc/xSPA1
sD88CwTaT9DQZMfqXjdcJ/nqBQlOfdXYxWs5zTGkGVdSC7DaThZG31s+0qht2WGT
1PyCLKg2SJK7HLIcWBd0apECgYEAnHz0svqCtFZ/k2JD9iLxeg34q/DviESfdbn9
FeXlF4uXVzY7i4mExZC9AcHUl8WMFX5IhgMUG1d+l3yMW0Tle7fv3PLwc5Uwee+9
nCowsTb7u9E0jw8b735xG1+F2fBPwQueU0+cLLM3QnYgp56Rio9nXDE2k0/wGd/p
Xhcm1P8CgYEAxIXFqJ1rWQh4MV9abLDFQ+cdLxn6tvmskxCA9LGcyaA+fFbcRx25
mYIAaRZI5SHjgMjeicDgPmY+xuNMSKcgd2C4uYJiW5xo7r+7SwcIyo6J8nZeZAVK
bxrMjPsOnAt3Tq7G0tlACxBOBhf+dcDW7D8/8EE6klKr2OrrT2Yag6k=
-----END RSA PRIVATE KEY-----`
*/
const testUserPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI09fpMWTeYw7/EO/+FywS/sghNXdTeTWxX7K2N17owsQJX8s76LGVIdVeYrWg4QSmYlpf6EVSCpx/fbCazrsG7FJVTRhExzFbRT9asmvzS+viXSbSvnavhOz/paihyaMsVPKVv24vF6MOs8DgfwehcKCPjKoIPnlYXZaZcy05KOcZmsvYu2kNOP6sSjDFF+ru+T+DLp3DUGw+MPr45IuR7iDnhXhklqyUn0d7ou0rOHXz9GdHIzpr+DAoQGmTDkpbQEo067Rjfu406gYL8pVFD1F7asCjU39llQCcU/HGyPym5fa29Nubw0dzZZXGZUVFalxo02YMM7P9I6ZjeCsv camilo_viecco1@mon-sre-dev.ash2.symcpe.net`

// func GenSSHCertFileString(username string, userPubKey string, signer ssh.Signer, host_identity string) (string, error) {
func TestGenSSHCertFileStringGenerateSuccess(t *testing.T) {
	username := "foo"
	hostIdentity := "bar"
	goodSigner, err := ssh.ParsePrivateKey([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	c, err := GenSSHCertFileString(username, testUserPublicKey, goodSigner, hostIdentity)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got '%s'", c)
}

func TestGetUserPubKeyFromSSSD(t *testing.T) {
	usr, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	username := usr.Username
	target := "9Z5PHgLIlUMUnu0MUv2p+RuJCwNXG9Lg/3tXpOau7UM="
	h := sha256.New()
	h.Write([]byte(username))
	b := h.Sum(nil)
	targetUser := base64.StdEncoding.EncodeToString(b)
	t.Logf("'%s'", targetUser)
	//username := usr.Username
	if username != target || usr.Name != usr.Name {
		t.SkipNow()
	}
	pk, err := GetUserPubKeyFromSSSD(username)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got ''%s", pk)

}
