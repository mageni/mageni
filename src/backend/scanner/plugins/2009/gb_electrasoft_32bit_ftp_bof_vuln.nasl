###############################################################################
# OpenVAS Vulnerability Test
#
# ElectraSoft 32bit FTP Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800569");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1592", "CVE-2009-1611", "CVE-2009-1675");
  script_bugtraq_id(34822, 34838);
  script_name("ElectraSoft 32bit FTP Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34993");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8614");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8613");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8623");
  script_xref(name:"URL", value:"http://www.electrasoft.com/readmef.txt");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50337");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_electrasoft_32bit_ftp_detect.nasl");
  script_mandatory_keys("ElectraSoft/FTP/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  codes within the context of the application by connecting to malicious
  FTP servers or can cause the application to crash.");
  script_tag(name:"affected", value:"ElectraSoft 32bit FTP 09.04.24 and prior on Windows");
  script_tag(name:"insight", value:"A boundary error occurs while processing,

  - response received from an FTP server with overly long banners.

  - a overly long 257 reply to a CWD command.

  - a overly long 227 reply to a PASV command.");
  script_tag(name:"solution", value:"Upgrade to 32bit FTP version 09.05.01.");
  script_tag(name:"summary", value:"This host is running ElectraSoft 32bit FTP client which is prone
  to Buffer Overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

bitftpVer = get_kb_item("ElectraSoft/FTP/Ver");
if(!bitftpVer)
  exit(0);

if(version_is_less_equal(version:bitftpVer, test_version:"09.04.24")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
