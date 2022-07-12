###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ffftp_untrusted_search_path_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# FFFTP Untrusted Search Path Vulnerability (Windows) - Dec 11
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902770");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-4266");
  script_bugtraq_id(51063);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-15 15:17:47 +0530 (Thu, 15 Dec 2011)");
  script_name("FFFTP Untrusted Search Path Vulnerability (Windows) - Dec 11");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47137/");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN94002296/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000104.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ffftp_detect.nasl");
  script_mandatory_keys("FFFTP/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute an arbitrary
  program in the context of the user running the affected application.");
  script_tag(name:"affected", value:"FFFTP version 1.98c and prior.");
  script_tag(name:"insight", value:"The flaw is due to an error when loading executables (readme.exe) in
  an insecure manner. This can be exploited to run an arbitrary program by
  tricking a user into opening a file located on a remote WebDAV or SMB share.");
  script_tag(name:"solution", value:"Upgrade to the FFFTP version 1.98d or later.");
  script_tag(name:"summary", value:"The host is running FFFTP and is prone to untrusted search path
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://sourceforge.jp/projects/ffftp/releases/");
  exit(0);
}


include("version_func.inc");

ftpVer = get_kb_item("FFFTP/Ver");
if(!ftpVer){
  exit(0);
}

if(version_is_less(version:ftpVer, test_version:"1.98.4.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
