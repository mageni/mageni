###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_labtam_proftp_welcome_bof_vuln.nasl 14335 2019-03-19 14:46:57Z asteins $
#
# Labtam ProFTP Welcome Message Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900980");
  script_version("$Revision: 14335 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:46:57 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3976");
  script_bugtraq_id(36128);
  script_name("Labtam ProFTP Welcome Message Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36446/");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9508");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2414");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_labtam_proftp_detect.nasl");
  script_mandatory_keys("Labtam/ProFTP/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue by executing arbitrary code by tricking a
  user into connecting to a malicious FTP server and to crash an application.");
  script_tag(name:"affected", value:"Labtam ProFTP version 2.9 and prior on Windows.");
  script_tag(name:"insight", value:"A boundary error occurs when processing overly long welcome message sent by
  a FTP server.");
  script_tag(name:"solution", value:"Upgrade to ProFTP Version 3.0 or later.");
  script_tag(name:"summary", value:"The host is installed with Labtam ProFTP and is prone to Buffer
  Overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.labtam-inc.com/index.php");
  exit(0);
}


include("version_func.inc");

pfVer = get_kb_item("Labtam/ProFTP/Ver");
if(!pfVer){
  exit(0);
}

if(version_is_less_equal(version:pfVer, test_version:"2.9")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
