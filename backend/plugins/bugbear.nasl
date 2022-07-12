# OpenVAS Vulnerability Test
# $Id: bugbear.nasl 13541 2019-02-08 13:21:52Z cfischer $
# Description: Bugbear worm
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Well, in fact I started from a simple script by Thomas Reinke and
# heavily hacked every byte of it :-]
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added links to the Bugtraq message archive and Microsoft Knowledgebase
#
# Copyright:
# Copyright (C) 2002 Michel Arboi & Thomas Reinke
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# There was no information on the BugBear protocol.
# I found a worm in the wild and found that it replied to the "p" command;
# the data look random but ends with "ID:"  and a number
# Thomas Reinke confirmed that his specimen of the worm behaved in the
# same way.
# We will not provide the full data here because it might contain
# confidential information.
#
# References:
#
# Date: Tue, 1 Oct 2002 02:07:29 -0400
# From:"Russ" <Russ.Cooper@RC.ON.CA>
# Subject: Alert:New worms, be aware of internal infection possibilities
# To:NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11135");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2524);
  script_cve_id("CVE-2001-0154"); # For MS01-020 - should be changed later
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Bugbear worm");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2002 Michel Arboi & Thomas Reinke");
  script_family("Malware");
  script_require_ports(36794);
  script_dependencies("find_service.nasl");
  script_tag(name:"solution", value:"- Use an Anti-Virus package to remove it.

  - Close your Windows shares

  - Update your IE browser

  See 'Incorrect MIME Header Can Cause IE to Execute E-mail Attachment'");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"summary", value:"BugBear backdoor is listening on this port.");

  script_tag(name:"impact", value:"An attacker may connect to it to retrieve secret
  information, e.g. passwords or credit card numbers.");

  script_tag(name:"insight", value:"The BugBear worm includes a key logger and can stop
  antivirus or personal firewall software. It propagates itself through email and open
  Windows shares.

  Depending on the antivirus vendor, it is known as: Tanatos,
  I-Worm.Tanatos, NATOSTA.A, W32/Bugbear-A, Tanatos, W32/Bugbear@MM,
  WORM_BUGBEAR.A, Win32.BugBear.");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS01-020.mspx");
  script_xref(name:"URL", value:"http://www.sophos.com/virusinfo/analyses/w32bugbeara.html");
  script_xref(name:"URL", value:"http://www.ealaddin.com/news/2002/esafe/bugbear.asp");
  script_xref(name:"URL", value:"http://securityresponse.symantec.com/avcenter/venc/data/w32.bugbear@mm.html");
  script_xref(name:"URL", value:"http://vil.nai.com/vil/content/v_99728.htm");
  script_xref(name:"URL", value:"http://online.securityfocus.com/news/1034");
  script_xref(name:"URL", value:"http://support.microsoft.com/default.aspx?scid=KB;en-us;329770&");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = 36794;

if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

# We just need to send a 'p' without CR
send(socket: soc, data: "p");
# I never saw a buffer bigger than 247 bytes but as the "ID:" string is
# near the end, we'd better use a big buffer, just in case
r = recv(socket: soc, length: 65536);
close(soc);

if ("ID:" >< r) {
 security_message(port);
 register_service(port: port, proto: "bugbear");
 exit(0);
}

msg = "
This port is usually used by the BugBear backdoor.
Although the scanner was unable to get an answer from the worm,
you'd better check your machine with an up to date
antivirus scanner.";
security_message(port: port, data: msg);