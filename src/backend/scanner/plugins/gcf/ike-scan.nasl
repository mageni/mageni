##############################################################################
# OpenVAS Vulnerability Test
# $Id: ike-scan.nasl 13743 2019-02-18 15:22:10Z cfischer $

# Description: ike-scan (NASL wrapper)
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr> (Original development and fixes to rewrite)
# Tim Brown <timb@openvas.org> (Complete rewrite)
#
# Copyright:
# Copyright (c) 2008 Vlatko Kosturjak
# Copyright (c) 2008 Tim Brown
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# Adapted code by from Hackin9/Uncon, and ported to perl and then NASL.
# Additional checks curtesy of NTA Monitor wiki at:
# <http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide>
#
# To do:
# * Script OIDs
# * Reference to known vulnerabilities
# * IKE v2 (not yet fully supported by ike-scan)
# * IKE over TCP
# * NAT-Traversal (RFC 3947)
# * Support for known vendor IDs
# * PSK crack
#
# Tested against Racoon and Openswan and used as part of a live
# penetration test against Checkpoint VPN-1 and Cisco VPN.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80000");
  script_version("$Revision: 13743 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 16:22:10 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-08-31 23:34:05 +0200 (Sun, 31 Aug 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ike-scan (NASL wrapper)");
  script_category(ACT_SCANNER);
  script_family("Port scanners");
  script_copyright("Copyright (C) 2008 Tim Brown and Vlatko Kosturjak");
  script_dependencies("ping_host.nasl", "toolcheck.nasl");
  script_mandatory_keys("Tools/Present/ike-scan");

  # Not sure how much value there is in supporting IKE v2
  #  script_add_preference(name:"Use IKE v2", type:"checkbox", value:"no");
  script_add_preference(name:"Source port number", type:"entry", value:"500");
  script_add_preference(name:"Destination port number", type:"entry", value:"500");
  script_add_preference(name:"Enable Aggressive Mode", type:"checkbox", value:"yes");
  script_add_preference(name:"Enable Main Mode", type:"checkbox", value:"no");
  script_add_preference(name:"Enable fingerprint using Aggressive Mode", type:"checkbox", value:"no");
  script_add_preference(name:"Enable fingerprint using Main Mode", type:"checkbox", value:"no");
  script_add_preference(name:"Group names", type:"entry", value:"vpn");
  # (["1", "DES"], ["2", "IDEA"], ["3", "Blowfish"], ["4", "RC5"], ["5", "3DES"], ["6", "CAST"], ["7/128", "AES-128"], ["7/196", "AES-196"], ["7/256", "AES-256"], ["8", "Camellia"]);
  script_add_preference(name:"Encryption algorithms", type:"entry", value:"1,2,3,4,5,6,7/128,7/196,7/256,8");
  # (["1", "MD5"], ["2", "SHA1"], ["3", "Tiger"], ["4", "SHA2-256"], ["5", "SHA2-384"], ["6", "SHA2-512"]);
  script_add_preference(name:"Hash algorithms", type:"entry", value:"1,2,3,4,5,6");
  # (["1", "PSK"], ["2", "DSS-Signature"], ["3", "RSA-Signature"], ["4", "RSA-Encryption"], ["5", "Revised-RSA-Encryption"], ["6", "ElGamel-Encryption"], ["7", "Revised-ElGamel-Encryption"], ["8", "ECDSA-Signature"], ["64221", "Hybrid"], ["65001", "XAUTH"]);
  script_add_preference(name:"Authentication methods", type:"entry", value:"1,2,3,4,5,6,7,8,64221,65001");
  # (["1", "MODP-768"], ["2", "MODP-1024"], ["3", "EC2N-155"], ["4", "EC2N-185"], ["5", "MODP-1536"]);
  # technically we should do 1-20 <http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide#Diffie-Hellman_Group_Values> but that's a bitch
  script_add_preference(name:"Diffie-Hellman groups", type:"entry", value:"1,2,3,4,5");
  script_add_preference(name:"Maximum retry", type:"entry", value:"3");
  script_add_preference(name:"Maximum timeout", type:"entry", value:"");

  script_tag(name:"summary", value:"ike-scan (NASL wrapper)

  This plugin runs ike-scan to identify IPSEC VPN endpoints. It will attempt to enumerate supported cipher suites,
  bruteforce valid groupnames and fingerprint any endpoint identified.

  Note: The plugin needs the 'ike-scan' binary found within the PATH of the user running the scanner and
  needs to be executable for this user. The existence of this binary is checked and reported separately
  within 'Availability of scanner helper tools' (OID: 1.3.6.1.4.1.25623.1.0.810000).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

if(!get_kb_item("Tools/Present/ike-scan"))
  exit(0);

encryptionalgorithmname["1"] = "DES";
encryptionalgorithmname["2"] = "IDEA";
encryptionalgorithmname["3"] = "Blowfish";
encryptionalgorithmname["4"] = "RC5";
encryptionalgorithmname["5"] = "3DES";
encryptionalgorithmname["6"] = "CAST";
encryptionalgorithmname["7/128"] = "AES-128";
encryptionalgorithmname["7/196"] = "AES-196";
encryptionalgorithmname["7/256"] = "AES-256";
encryptionalgorithmname["8"] = "Camellia";
hashalgorithmname["1"] = "MD5";
hashalgorithmname["2"] = "SHA1";
hashalgorithmname["3"] = "Tiger";
hashalgorithmname["4"] = "SHA2-256";
hashalgorithmname["5"] = "SHA2-384";
hashalgorithmname["6"] = "SHA2-512";
authenticationmethodname["1"] = "PSK";
authenticationmethodname["2"] = "DSS-Signature";
authenticationmethodname["3"] = "RSA-Signature";
authenticationmethodname["4"] = "RSA-Encryption";
authenticationmethodname["5"] = "Revised-RSA-Encryption";
authenticationmethodname["6"] = "ElGamel-Encryption";
authenticationmethodname["7"] = "Revised-ElGamel-Encryption";
authenticationmethodname["8"] = "ECDSA-Signature";
authenticationmethodname["64221"] = "Hybrid";
authenticationmethodname["65001"] = "XAUTH";
diffiehellmangroupname["1"] = "MODP-768";
diffiehellmangroupname["2"] = "MODP-1024";
diffiehellmangroupname["3"] = "EC2N-155";
diffiehellmangroupname["4"] = "EC2N-185";
diffiehellmangroupname["5"] = "MODP-1536";
lockfilename = "";

function on_exit()
{
	unlink(lockfilename);
}

function command_construct(_ike2flag, _sourceportnumber, _destinationportnumber, _checkmode, _fingerprintmode, _groupname, _encryptionalgorithm, _hashalgorithm, _authenticationmethod, _diffiehellmangroup, _maximumretry, _maximumtimeout, _destinationipaddress)
{
	_argumentcounter = 0;
	_commandarguments[_argumentcounter ++] = "ike-scan";
	# Not sure how much value there is in supporting IKE v2
	#if (_ike2flag == "yes")
	#{
	#	_commandarguments[_argumentcounter ++] = "--ikev2";
	#}
	if (_sourceportnumber != "")
	{
		_commandarguments[_argumentcounter ++] = "--sport=" + _sourceportnumber;
	}
	if (_destinationportnumber != "")
	{
		_commandarguments[_argumentcounter ++] = "--dport=" + _destinationportnumber;
	}
	if (_checkmode != "")
	{
		_commandarguments[_argumentcounter ++] = _checkmode;
	}
	if (_fingerprintmode != "")
	{
		_commandarguments[_argumentcounter ++] = _fingerprintmode;
	}
	if (_groupname != "")
	{
		_commandarguments[_argumentcounter ++] = "--id=" + _groupname;
	}
	_commandarguments[_argumentcounter ++] = "--trans=" + _encryptionalgorithm + "," + _hashalgorithm + "," + _authenticationmethod + "," + _diffiehellmangroup;
	if (_maximumretry)
	{
		_commandarguments[_argumentcounter ++] = "--retry=" + _maximumretry;
	}
	if (_maximumtimeout)
	{
		_commandarguments[_argumentcounter ++] = "--timeount=" + _maximumtimeout;
	}
	_commandarguments[_argumentcounter ++] = _destinationipaddress;
	return _commandarguments;
}

function command_parse(_responsedata, _securitynote, _destinationipaddress, _port)
{
	if ((_destinationipaddress >< _responsedata) && ("NO-PROPOSAL-CHOSEN" >!< _responsedata))
	{
		scanner_add_port(proto:"udp", port:_port);
		_data = "IPSEC VPN endpoint detected.

" + _securitynote + "

ike-scan returned:

" + _responsedata;
		log_message(proto:"udp", port:_port, data:_data);
	}
	else
	{
		if (_destinationipaddress >< _responsedata)
		{
			scanner_add_port(proto:"udp", port:_port);
		}
	}
}

# Basic locking mechanism as multiple ike-scans launched are not
# supported because you cannot bind to same UDP port twice locally
lockdirectoryname = get_tmp_dir();
lockfilename = lockdirectoryname + "openvas-nasl-ike-scan";

# bladyjoker told on IRC that, if openvassd crashed, the lock-file was not removed and scan never stops.
start = unixtime();

if(file_stat(lockfilename)) {

  ul = fread(lockfilename);
  if(start > (int(ul)+900)) { # If the lock file is older than 15 minutes remove it.
      unlink(lockfilename);
  }

}

while (file_stat(lockfilename) > 0)
{
	usleep(1000 + (rand() % 1000));
}
fwrite(data:string(start), file:lockfilename);

# Not sure how much value there is in supporting IKE v2
#ike2flag = script_get_preference("Use IKE v2");
ike2flag = NULL;
sourceportnumber = script_get_preference("Source port number");
destinationportnumber = script_get_preference("Destination port number");
if (islocalhost() && (sourceportnumber == destinationportnumber)) {
	scanner_status(current:4, total:4);
	set_kb_item(name:"Host/scanned", value:TRUE);
	set_kb_item(name:'Host/scanners/ike-scan', value:TRUE);
	exit(0);
}
aggressivemodeflag = script_get_preference("Enable Aggressive Mode");
mainmodeflag = script_get_preference("Enable Main Mode");
fingerprintaggressivemodeflag = script_get_preference("Enable fingerprint using Aggressive Mode");
fingerprintmainmodeflag = script_get_preference("Enable fingerprint using Main Mode");
groupnames = script_get_preference("Group names");
encryptionalgorithms = script_get_preference("Encryption algorithms");
hashalgorithms = script_get_preference("Hash algorithms");
authenticationmethods = script_get_preference("Authentication methods");
diffiehellmangroups = script_get_preference("Diffie-Hellman groups");
maximumretry = script_get_preference("Maximum retry");
maximumtimeout = script_get_preference("Maximum timeout");
destinationipaddress = get_host_ip();
if (aggressivemodeflag == "yes")
{
	foreach groupname (split(groupnames, sep:",", keep:FALSE))
	{
		foreach encryptionalgorithm (split(encryptionalgorithms, sep:",", keep:FALSE))
		{
			foreach hashalgorithm (split(hashalgorithms, sep:",", keep:FALSE))
			{
				foreach authenticationmethod (split(authenticationmethods, sep:",", keep:FALSE))
				{
					foreach diffiehellmangroup (split(diffiehellmangroups, sep:",", keep:FALSE))
					{
						commandarguments = command_construct(_ike2flag:ike2flag, _sourceportnumber:sourceportnumber, _destinationportnumber:destinationportnumber, _checkmode:"--aggressive", _groupname:groupname, _encryptionalgorithm:encryptionalgorithm, _hashalgorithm:hashalgorithm, _authenticationmethod:authenticationmethod, _diffiehellmangroup:diffiehellmangroup, _maximumretry:maximumretry, _maximumtimeout:maximumtimeout, _destinationipaddress:destinationipaddress);
						responsedata = pread(cmd:"ike-scan", argv:commandarguments, cd:1, nice:5);
						securitynote = "Aggressive Mode Handshaking succeeded using groupname=" + groupname + ", encryption algorithm=" + encryptionalgorithmname[encryptionalgorithm] + "(" + encryptionalgorithm + "), hash algorithm=" + hashalgorithmname[hashalgorithm] + "(" + hashalgorithm + "), authentication method=" + authenticationmethodname[authenticationmethod] + "(" + authenticationmethod + "), diffie-hellman group=" + diffiehellmangroupname[diffiehellmangroup] + "(" + diffiehellmangroup + ").

Since the VPN endpoint answers to requests using IKE Aggressive Mode Handshaking, an attacker could potentially carry out a bruteforce attack against this host.";
						command_parse(_responsedata:responsedata, _securitynote:securitynote, _destinationipaddress:destinationipaddress, _port:destinationportnumber);
					}
				}
			}
		}
	}
}
scanner_status(current:1, total:4);
if (mainmodeflag == "yes")
{
	foreach encryptionalgorithm (split(encryptionalgorithms, sep:",", keep:FALSE))
	{
		foreach hashalgorithm (split(hashalgorithms, sep:",", keep:FALSE))
		{
			foreach authenticationmethod (split(authenticationmethods, sep:",", keep:FALSE))
			{
				foreach diffiehellmangroup (split(diffiehellmangroups, sep:",", keep:FALSE))
				{
					commandarguments = command_construct(_ike2flag:ike2flag, _sourceportnumber:sourceportnumber, _destinationportnumber:destinationportnumber, _checkmode:"", _groupname:"", _encryptionalgorithm:encryptionalgorithm, _hashalgorithm:hashalgorithm, _authenticationmethod:authenticationmethod, _diffiehellmangroup:diffiehellmangroup, _maximumretry:maximumretry, _maximumtimeout:maximumtimeout, _destinationipaddress:destinationipaddress);
					responsedata = pread(cmd:"ike-scan", argv:commandarguments, cd:1, nice:5);
					securitynote = "Main Mode Handshaking succeeded using groupname=" + groupname + ", encryption algorithm=" + encryptionalgorithmname[encryptionalgorithm] + "(" + encryptionalgorithm + "), hash algorithm=" + hashalgorithmname[hashalgorithm] + "(" + hashalgorithm + "), authentication method=" + authenticationmethodname[authenticationmethod] + "(" + authenticationmethod + "), diffie-hellman group=" + diffiehellmangroupname[diffiehellmangroup] + "(" + diffiehellmangroup + ").";
					command_parse(_responsedata:responsedata, _securitynote:securitynote, _destinationipaddress:destinationipaddress, _port:destinationportnumber);
				}
			}
		}
	}
}
scanner_status(current:2, total:4);
if (fingerprintaggressivemodeflag == "yes")
{
	foreach groupname (split(groupnames, sep:",", keep:FALSE))
	{
		foreach encryptionalgorithm (split(encryptionalgorithms, sep:",", keep:FALSE))
		{
			foreach hashalgorithm (split(hashalgorithms, sep:",", keep:FALSE))
			{
				foreach authenticationmethod (split(authenticationmethods, sep:",", keep:FALSE))
				{
					foreach diffiehellmangroup (split(diffiehellmangroups, sep:",", keep:FALSE))
					{
						commandarguments = command_construct(_ike2flag:ike2flag, _sourceportnumber:sourceportnumber, _destinationportnumber:destinationportnumber, _checkmode:"--aggressive", _fingerprintmode:"--showbackoff", _groupname:groupname, _encryptionalgorithm:encryptionalgorithm, _hashalgorithm:hashalgorithm, _authenticationmethod:authenticationmethod, _diffiehellmangroup:diffiehellmangroup, _maximumretry:maximumretry, _maximumtimeout:maximumtimeout, _destinationipaddress:destinationipaddress);
						responsedata = pread(cmd:"ike-scan", argv:commandarguments, cd:1, nice:5);
						securitynote = "Fingerprinting Aggressive Mode succeeded using groupname=" + groupname + ", encryption algorithm=" + encryptionalgorithmname[encryptionalgorithm] + "(" + encryptionalgorithm + "), hash algorithm=" + hashalgorithmname[hashalgorithm] + "(" + hashalgorithm + "), authentication method=" + authenticationmethodname[authenticationmethod] + "(" + authenticationmethod + "), diffie-hellman group=" + diffiehellmangroupname[diffiehellmangroup] + "(" + diffiehellmangroup + ").

Since the VPN endpoint answers to requests using IKE Aggressive Mode Handshaking, an attacker could potentially carry out a bruteforce attack against this host.";
						command_parse(_responsedata:responsedata, _securitynote:securitynote, _destinationipaddress:destinationipaddress, _port:destinationportnumber);
					}
				}
			}
		}
	}
}
scanner_status(current:3, total:4);
if (fingerprintmainmodeflag == "yes")
{
	foreach encryptionalgorithm (split(encryptionalgorithms, sep:",", keep:FALSE))
	{
		foreach hashalgorithm (split(hashalgorithms, sep:",", keep:FALSE))
		{
			foreach authenticationmethod (split(authenticationmethods, sep:",", keep:FALSE))
			{
				foreach diffiehellmangroup (split(diffiehellmangroups, sep:",", keep:FALSE))
				{
					commandarguments = command_construct(_ike2flag:ike2flag, _sourceportnumber:sourceportnumber, _destinationportnumber:destinationportnumber, _checkmode:"", _fingerprintmode:"--showbackoff", _groupname:"", _encryptionalgorithm:encryptionalgorithm, _hashalgorithm:hashalgorithm, _authenticationmethod:authenticationmethod, _diffiehellmangroup:diffiehellmangroup, _maximumretry:maximumretry, _maximumtimeout:maximumtimeout, _destinationipaddress:destinationipaddress);
					responsedata = pread(cmd:"ike-scan", argv:commandarguments, cd:1, nice:5);
					securitynote = "Fingerprinting Main Mode succeeded using groupname=" + groupname + ", encryption algorithm=" + encryptionalgorithmname[encryptionalgorithm] + "(" + encryptionalgorithm + "), hash algorithm=" + hashalgorithmname[hashalgorithm] + "(" + hashalgorithm + "), authentication method=" + authenticationmethodname[authenticationmethod] + "(" + authenticationmethod + "), diffie-hellman group=" + diffiehellmangroupname[diffiehellmangroup] + "(" + diffiehellmangroup + ").";
					command_parse(_responsedata:responsedata, _securitynote:securitynote, _destinationipaddress:destinationipaddress, _port:destinationportnumber);
				}
			}
		}
	}
}
scanner_status(current:4, total:4);
set_kb_item(name:"Host/scanned", value:TRUE);
set_kb_item(name:'Host/scanners/ike-scan', value:TRUE);
