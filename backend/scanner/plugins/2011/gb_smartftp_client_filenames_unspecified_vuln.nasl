###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smartftp_client_filenames_unspecified_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# SmartFTP Filename Processing Unspecified Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801992");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2010-4871");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SmartFTP Filename Processing Unspecified Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42060");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/63113");
  script_xref(name:"URL", value:"https://www.smartftp.com/forums/index.php?/topic/16425-smartftp-client-40-change-log/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_smartftp_client_detect.nasl");
  script_mandatory_keys("SmartFTP/Client/Ver");
  script_tag(name:"insight", value:"An unspecified flaw exists in SmartFTP when processing filenames, has an
  unknown impact and attack vector.");
  script_tag(name:"solution", value:"Update SmartFTP Client to version 4.0 Build 1142 or later.");
  script_tag(name:"summary", value:"This host is installed with SmartFTP Client and is prone to
  unspecified vulnerability.");
  script_tag(name:"impact", value:"Has an unknown impact and attack vector.");
  script_tag(name:"affected", value:"SmartFTP Client version prior to 4.0.1142.0");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.smartftp.com/download/");
  exit(0);

}


include("version_func.inc");

sftpVer = get_kb_item("SmartFTP/Client/Ver");
if(sftpVer != NULL)
{
  if(version_is_less(version:sftpVer, test_version:"4.0.1142.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
