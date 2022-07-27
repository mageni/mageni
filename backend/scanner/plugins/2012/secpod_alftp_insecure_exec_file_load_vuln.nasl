###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_alftp_insecure_exec_file_load_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# ALFTP Insecure Executable File Loading Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903012");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-0315");
  script_bugtraq_id(51984);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("ALFTP Insecure Executable File Loading Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-28 10:36:31 +0530 (Wed, 28 Mar 2012)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48027/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51984");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN85695061/index.html");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN85695061/995223/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000011.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw is due to the application loading executables (readme.exe)
  in an insecure manner. This can be exploited to run an arbitrary program by
  tricking a user into opening a file located on a remote WebDAV or SMB share.");
  script_tag(name:"solution", value:"Upgrade to the ALFTP version 5.31 or later.");
  script_tag(name:"summary", value:"This host is installed with ALFTP and is prone to insecure
  executable file loading vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"ALFTP version prior to 5.31");
  script_xref(name:"URL", value:"http://www.altools.jp/download/ALFTP.aspx");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\ESTsoft\ALFTP";
if(!registry_key_exists(key:key)){
  exit(0);
}

alftpVer = registry_get_sz(key:key, item:"Version");
if(alftpVer)
{
  if(version_is_less(version:alftpVer, test_version:"5.31")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
