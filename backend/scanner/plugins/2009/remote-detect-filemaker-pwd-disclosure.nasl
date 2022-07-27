# OpenVAS Vulnerability Test
# $Id: remote-detect-filemaker-pwd-disclosure.nasl 14325 2019-03-19 13:35:02Z asteins $
# Description: FileMaker Pro Client Authentication User Password Disclosure Vulnerability
#
# remote-detect-filemaker-pwd-disclosure.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# Vulnerable:
# FileMaker FileMaker Server 5.5
# FileMaker FileMaker Server 5.0
# FileMaker FileMaker Pro 6.0 Unlimited
# FileMaker FileMaker Pro 6.0
# FileMaker FileMaker Pro 5.5 Unlimited
# FileMaker FileMaker Pro 5.5
# FileMaker FileMaker Pro 5.0
# - Apple Mac OS 8 8.6
# - Apple Mac OS 8 8.6
# - Apple Mac OS 8 8.5
# - Apple Mac OS 8 8.5
# - Apple Mac OS 8 8.1
# - Apple Mac OS 8 8.1
# - Apple Mac OS 8 8.0
# - Apple Mac OS 8 8.0
# - Apple Mac OS 9 9.0
# - Microsoft Windows NT 4.0
# - Microsoft Windows NT 4.0
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101001");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-08 15:05:20 +0100 (Sun, 08 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(7315);
  script_name("FileMaker Pro User Password Disclosure Vulnerability");

  script_tag(name:"qod_type", value:"remote_vul");

  script_category(ACT_ATTACK);

  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Brute force attacks");
  script_dependencies("remote-detect-filemaker.nasl");
  script_require_keys("FileMaker/installed");
  script_require_ports(5003);

  script_tag(name:"summary", value:"The remote Filemaker database server is prone to a User Password Disclosure Vulnerability,
because it does not properly secure credentials during authentication.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

if(!get_kb_item("FileMaker/installed")) exit(0);

port = 5003;

if(get_port_state(port))
{
	soc = open_sock_tcp(port);
	if(soc)
	{
		filemaker_auth_packet = "\x00\x04\x13\x00";
		send(socket:soc, data: filemaker_auth_packet);
		reply = recv(socket:soc, length:3);

		if(reply ==  "\x00\x06\x14") {
			security_message(port:port, data:"The target host was found to be vulnerable.");
      exit(0);
    }
	}
}

exit(99);
