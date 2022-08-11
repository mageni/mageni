###############################################################################
# OpenVAS Vulnerability Test
#
# IrfanView Integer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900377");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2118");
  script_bugtraq_id(35423);
  script_name("IrfanView Integer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35359");
  script_xref(name:"URL", value:"http://www.irfanview.com/main_history.htm");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_irfanview_detect.nasl");
  script_mandatory_keys("IrfanView/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause Integer Overflow when
  screen fitting option is enabled.");
  script_tag(name:"affected", value:"IrfanView version prior to 4.25");
  script_tag(name:"insight", value:"This flaw is generated because the application fails to perform proper
  boundary checks while opening a specially crafted TIFF 1 BPP images
  which can exploited to cause a heap based buffer overflow.");
  script_tag(name:"solution", value:"Upgrade to version 4.25.");
  script_tag(name:"summary", value:"This host has IrfanView installed and is prone to Integer Overflow
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

irViewVer = get_kb_item("IrfanView/Ver");
if(!irViewVer)
  exit(0);

if(version_is_less(version:irViewVer, test_version:"4.25")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
