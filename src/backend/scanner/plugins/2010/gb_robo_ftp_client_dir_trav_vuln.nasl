###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_robo_ftp_client_dir_trav_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Robo-FTP Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801626");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-11-16 10:37:01 +0100 (Tue, 16 Nov 2010)");
  script_bugtraq_id(44073);
  script_cve_id("CVE-2010-4095");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Robo-FTP Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41809");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62548");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/directory_traversal_vulnerability_in_robo_ftp.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_robo_ftp_client_detect.nasl");
  script_mandatory_keys("Robo/FTP/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to download or upload arbitrary
  files. This may aid in further attacks.");
  script_tag(name:"affected", value:"Robo-FTP versions prior to 3.7.5.");
  script_tag(name:"insight", value:"This flaw is due to an input validation error when downloading
  directories containing files with directory traversal specifiers in the
  filename. This can be exploited to download files to an arbitrary location
  on a user's system.");
  script_tag(name:"solution", value:"Upgrade to Robo-FTP version 3.7.5 or later.");
  script_tag(name:"summary", value:"This host is installed with Robo-FTP and is prone to directory
  traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.robo-ftp.com/download/");
  exit(0);
}


include("version_func.inc");

roboVer = get_kb_item("Robo/FTP/Ver");

if(roboVer != NULL)
{
  if(version_is_less(version:roboVer, test_version:"3.7.5") ){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
