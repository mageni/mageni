###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_cisco_default_ssh_host_key_75418.nasl 13568 2019-02-11 10:22:27Z cfischer $
#
# Multiple Cisco Products Default SSH Host Keys Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105319");
  script_bugtraq_id(75418);
  script_cve_id("CVE-2015-4217");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 13568 $");

  script_name("Multiple Cisco Products Default SSH Host Keys Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75418");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150625-ironport");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass security restrictions and
  perform unauthorized actions. This may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Check the remote ssh host keys.");

  script_tag(name:"insight", value:"The vulnerability is due to the presence of default SSH host keys that are shared across all the installations of WSAv,
  ESAv, and SMAv. An attacker could exploit this vulnerability by obtaining one of the SSH private keys and using it to impersonate or decrypt communication
  between any WSAv, ESAv, or SMAv. An exploit could allow the attacker to decrypt and impersonate secure communication between any virtual content security appliances.");

  script_tag(name:"solution", value:"Updates are available. Please see the vendor advisory for more information.");
  script_tag(name:"summary", value:"Multiple Cisco products are prone to a security-bypass vulnerability.");

  script_tag(name:"affected", value:"Cisco Web Security Virtual Appliance (WSAv), Cisco Email Security Virtual Appliance (ESAv), and Cisco Security Management Virtual Appliance (SMAv) are affected.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-08-14 13:28:44 +0200 (Fri, 14 Aug 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "ssh_proto_version.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  exit(0);
}

include("ssh_func.inc");

port = get_ssh_port(default:22);

fingerprint = get_kb_item("SSH/" + port + "/fingerprint/ssh-rsa");
if( ! fingerprint )
  exit( 0 );

known_fingerprints = make_list( "5e:78:99:f3:11:89:c2:60:ac:63:53:8f:48:d6:8f:a3",
                                "f0:67:d0:64:b5:56:b8:8e:f9:4a:c3:c9:5d:a4:2a:21",
                                "52:f5:c2:f1:b0:7f:dc:bb:eb:70:92:70:be:ed:a5:ee"
                              );

foreach kf ( known_fingerprints )
{
  if( kf == fingerprint )
  {
    report = 'The remote host is using the following default SSH host key: ' + fingerprint + '\n';
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );