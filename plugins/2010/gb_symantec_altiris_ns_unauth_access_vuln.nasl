###############################################################################
# OpenVAS Vulnerability Test
#
# Symantec Altiris NS Key Unauthorized Access Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800985");
  script_version("2019-05-17T12:32:34+0000");
  script_tag(name:"last_modification", value:"2019-05-17 12:32:34 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3035");
  script_bugtraq_id(37953);
  script_name("Symantec Altiris NS Key Unauthorized Access Vulnerability");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_symantec_altiris_ns_detect.nasl");
  script_mandatory_keys("Symantec/AltirisNS/Ver", "Symantec/AltirisNS/SP");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation let attackers to access certain encrypted credentials
  and encryption keys and also execute code, obtain sensitive information, or perform actions with elevated privileges.");

  script_tag(name:"affected", value:"Symantec Altiris Notification Server versions 6.0.x before 6.0 SP3 R12.");

  script_tag(name:"insight", value:"The flaw is due to the application using a static encryption key to
  encrypt and store certain credentials.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to Symantec Altiris Notification Server 6.0 SP3 R12.");

  script_tag(name:"summary", value:"This host is installed with Symantec Altiris Notification Server
  and is prone to unauthorized access vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38356");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55952");
  script_xref(name:"URL", value:"http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2010&suid=20100128_00");
  script_xref(name:"URL", value:"https://kb.altiris.com/article.asp?article=46763&p=1");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

httpPort = get_http_port(default:80);

sndReq = http_get(item:"/Altiris/NS/logview.asp", port:httpPort);
rcvRes = http_keepalive_send_recv(port:httpPort, data:sndReq, bodyonly:0);
if((isnull(rcvRes)) && ("Altiris NS " >!< rcvRes)){
  exit(0);
}

altirisVer = get_kb_item("Symantec/AltirisNS/Ver");
if(!altirisVer){
  exit(0);
}

spVer= get_kb_item("Symantec/AltirisNS/SP");
if((spVer == NULL) && (altirisVer =~ "^6\.0"))
{
  if(version_is_less_equal(version:altirisVer, test_version:"6.0.6074"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

else if(spVer =~ "^6\.0")
{
  if(version_is_less(version:spVer, test_version:"6.0.1210.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
