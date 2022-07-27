###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_irfanview_bof_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# IrfanView Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801338");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1510", "CVE-2010-1509");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("IrfanView Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39036");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-41");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_irfanview_detect.nasl");
  script_mandatory_keys("IrfanView/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to allow execution of arbitrary
  code or to compromise a user's system.");
  script_tag(name:"affected", value:"IrfanView version prior to 4.27");
  script_tag(name:"solution", value:"Upgrade to version 4.27 or later.");
  script_tag(name:"summary", value:"This host has IrfanView installed and is prone to buffer overflow
  vulnerabilities.");
  script_tag(name:"insight", value:"The flaws are due to,

  - A sign extension error when parsing certain 'PSD' images

  - A boundary error when processing certain 'RLE' compressed 'PSD' images.

   These can be exploited to cause a heap-based buffer overflow by tricking a
   user into opening a specially crafted PSD file.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.irfanview.com");
  exit(0);
}


include("version_func.inc");

irViewVer = get_kb_item("IrfanView/Ver");
if(!irViewVer){
  exit(0);
}

if(version_is_less(version:irViewVer, test_version:"4.27")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
