import argparse
import os
import sys
from glob import glob
from os.path import dirname, join

from ciphey import decrypt
from ciphey.iface import Config
from librairies.Rsa_files.RSA import Rsa


def main():
    parser = argparse.ArgumentParser(description=("Decrypt (almost) Everything !"))
    # Args for cesar
    parser.add_argument('-c', '--cesar', help='The sentence to decipher')
    # Args for Transbase
    parser.add_argument("-d", help="Decodes a simple cipher")
    # Args for Rsa_files
    parser.add_argument("--rsa", help="Enables rsa mode")
    parser.add_argument(
        "--publickey", help="public key file. You can use wildcards for multiple keys."
    )
    parser.add_argument(
        "--dumpkey",
        help="Just dump the RSA variables from a key - n,e,d,p,q",
        action="store_true",
    )
    parser.add_argument(
        "--ext",
        help="Extended dump of RSA private variables in --dumpkey mode - dp,dq,pinv,qinv).",
        action="store_true",
    )
    parser.add_argument("--uncipherfile", help="uncipher a file, using commas to separate multiple paths", default=None)
    parser.add_argument("--uncipher", help="uncipher a cipher, using commas to separate multiple ciphers", default=None)
    parser.add_argument(
        "--ecmdigits",
        type=int,
        help="Optionally an estimate as to how long one of the primes is for ECM method",
        default=None,
    )
    parser.add_argument("-n", help="Specify the modulus. format : int or 0xhex")
    parser.add_argument(
        "-p", help="Specify the first prime number. format : int or 0xhex"
    )
    parser.add_argument(
        "-q", help="Specify the second prime number. format : int or 0xhex"
    )
    parser.add_argument("-e",
                        help="Specify the public exponent, using commas to separate multiple exponents. format : int or 0xhex")
    parser.add_argument("--key", help="Specify the private key file.")
    parser.add_argument("--password", help="Private key password if needed.")
    parser.add_argument(
        "--nsif",
        type=int,
        help="Nos Santos Izquierdo Field, Integer valuer to start the crack, the loop is +1",
        default=None,
    )
    parser.add_argument(
        "--nsif-limit",
        type=int,
        help="The field to stop the crack",
        default=None,
    )

    parser.add_argument(
        "--dev_carmichael",
        help="Show carmichael derivation",
        default=None,
    )
    parser.add_argument(
        "--falzorize",
        type=int,
        help="Show P Q, the factors of N",
        default=None,
    )
    # Dynamic load all attacks for choices in argparse
    attacks = glob(join(dirname(os.path.realpath(__file__)), "attacks", "single_key", "*.py"))
    attacks += glob(
        join(dirname(os.path.realpath(__file__)), "attacks", "multi_keys", "*.py")
    )

    attacks_filtered = [
        basename(f)[:-3] for f in attacks if isfile(f) and not f.endswith("__init__.py")
    ]
    attacks_list = [_ for _ in attacks_filtered if _ != "nullattack"] + ["all"]
    parser.add_argument(
        "--attack",
        help="Specify the attack modes.",
        default="all",
        nargs="+",
        choices=attacks_list,
    )
    parser.add_argument(
        "--sendtofdb", help="Send results to factordb", action="store_true"
    )
    parser.add_argument(
        "--isconspicuous", help="conspicuous key check", action="store_true"
    )
    parser.add_argument(
        "--isroca", help="Check if given key is roca", action="store_true"
    )

    args = parser.parse_args()
    args = vars(args)

    # If there is no argument specified : launch the help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if args['d'] is not None:
        print(decrypt(Config().library_default().complete_config(),args['d'],))

    #RSA section
    if args['rsa'] is not None:
        Rsa(args,attacks,attacks_filtered,attacks_list)




if __name__ == '__main__':
    main()
