###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_trellian_ftp_bof_vuln.nasl 11553 2018-09-22 14:22:01Z cfischer $
#
# Trellian FTP 'PASV' Response Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901106");
  script_version("$Revision: 11553 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2010-1465");
  script_bugtraq_id(39598);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Trellian FTP 'PASV' Response Buffer Overflow Vulnerability");


  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("FTP");
  script_dependencies("secpod_trellian_ftp_detect.nasl");
  script_mandatory_keys("TrellianFTP/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
arbitrary code within the context of the affected application.");
  script_tag(name:"affected", value:"Trellian FTP version 3.1.3.1789 and prior.");
  script_tag(name:"insight", value:"The flaw is due to improper bounds checking when processing
long FTP 'PASV' responses.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Trellian FTP and is prone to buffer
overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39370");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57778");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12152");
  exit(0);
}


include("version_func.inc");

trellianVer = get_kb_item("TrellianFTP/Version");

if(trellianVer)
{
  if(version_is_less_equal(version:trellianVer, test_version:"3.1.3.1789")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
