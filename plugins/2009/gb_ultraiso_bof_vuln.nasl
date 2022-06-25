###############################################################################
# OpenVAS Vulnerability Test
#
# UltraISO Buffer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800275");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1260");
  script_bugtraq_id(34363);
  script_name("UltraISO Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34581");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8343");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49672");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_ultraiso_detect.nasl");
  script_mandatory_keys("UltraISO/Ver");
  script_tag(name:"affected", value:"UltraISO version 9.3.3.2685 and prior.");
  script_tag(name:"insight", value:"This flaw is due to inadequate boundary check while processing 'CCD'
  or 'IMG' files.");
  script_tag(name:"solution", value:"Upgrade to UltraISO version 9.3.6.2750 or later.");
  script_tag(name:"summary", value:"This host is running UltraISO and is prone to Stack-Based Buffer
  Overflow Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can cause stack overflow or denial of service.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ultraVer = get_kb_item("UltraISO/Ver");
if(!ultraVer)
  exit(0);

if(version_is_less_equal(version:ultraVer, test_version:"9.3.3.2685")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
