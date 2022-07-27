###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_clamav_recursion_dos_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# ClamAV Recursion Level Handling Denial of Service Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902760");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-3627");
  script_bugtraq_id(50183);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-22 17:51:52 +0530 (Tue, 22 Nov 2011)");
  script_name("ClamAV Recursion Level Handling Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/USN-1258-1/");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=746984");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=3d664817f6ef833a17414a4ecea42004c35cc42f");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_detect_win.nasl");
  script_mandatory_keys("ClamAV/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of service
  (crash) via vectors related to recursion level.");
  script_tag(name:"affected", value:"ClamAV before 0.97.3 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to the way the bytecode engine handled recursion
  level when scanning an unpacked file.");
  script_tag(name:"solution", value:"Upgrade to ClamAV version 0.97.3 or later");
  script_tag(name:"summary", value:"The host is installed with ClamAV and is prone to denial of service
  vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.clamav.net/lang/en/download/");
  exit(0);
}


include("version_func.inc");

avVer = get_kb_item("ClamAV/Win/Ver");
if(avVer == NULL){
  exit(0);
}

if(version_is_less(version:avVer, test_version:"0.97.3")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
