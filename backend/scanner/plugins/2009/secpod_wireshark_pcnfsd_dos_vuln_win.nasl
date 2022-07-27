###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_pcnfsd_dos_vuln_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Wireshark PCNFSD Dissector Processing Denial of Service Vulnerability (Windows)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900559");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1829");
  script_bugtraq_id(35081);
  script_name("Wireshark PCNFSD Dissector Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1408");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the user crash the application to cause
  denial of service condition.");

  script_tag(name:"affected", value:"Wireshark version 0.8.20 through 1.0.7 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an error in the PCNFSD dissector when processing specially
  crafted large PCNFSD packets.");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.0.8.");

  script_tag(name:"summary", value:"The remote host is installed with Wireshark and is prone to
  denial of service vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

if(version_in_range(version:sharkVer, test_version:"0.8.20", test_version2:"1.0.7")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
