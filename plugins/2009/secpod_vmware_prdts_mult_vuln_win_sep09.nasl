###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Products Multiple Vulnerabilities (Windows) sep09
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901020");
  script_version("2019-04-30T06:12:35+0000");
  script_tag(name:"last_modification", value:"2019-04-30 06:12:35 +0000 (Tue, 30 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0199", "CVE-2009-2628");
  script_bugtraq_id(36290);
  script_name("VMware Products Multiple Vulnerabilities (Windows) sep09");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/444513");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-25/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2553");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2009-0012.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2009/000065.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a heap-based buffer
  overflow via a specially crafted video file with mismatched dimensions.");
  script_tag(name:"affected", value:"VMware Workstation versions prior to 6.5.3 Build 185404
  VMware Player versions prior to 2.5.3 build 185404");
  script_tag(name:"insight", value:"The multiple flaws are due to,

  - An heap overflow error in the VMnc codec (vmnc.dll) when processing a video
    file with mismatched dimension.

  - An heap corruption error in the VMnc codec (vmnc.dll) when processing a video
    with a height of less than 8 pixels.");
  script_tag(name:"summary", value:"The host is installed with VMWare products and are prone to multiple
  vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade the VMWare product(s) according to the referenced vendor announcement.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed"))
  exit(0);

vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer)
{
  if(version_is_less(version:vmplayerVer, test_version:"2.5.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer)
{
  if(version_is_less(version:vmworkstnVer, test_version:"6.5.3")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
