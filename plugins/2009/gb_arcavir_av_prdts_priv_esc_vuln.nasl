###############################################################################
# OpenVAS Vulnerability Test
#
# ArcaVir AntiVirus Products Privilege Escalation Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800720");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-06-04 07:18:37 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(35100);
  script_cve_id("CVE-2009-1824");
  script_name("ArcaVir AntiVirus Products Privilege Escalation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35260");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8782");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1428");
  script_xref(name:"URL", value:"http://ntinternals.org/ntiadv0814/ntiadv0814.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_arcavir_av_prdts_detect.nasl");
  script_mandatory_keys("ArcaVir/AntiVirus/Ver");
  script_tag(name:"affected", value:"ArcaBit 2009 Home Protection prior to 9.4.3204.9

  ArcaVir 2009 System Protection prior to 9.4.3203.9

  ArcaVir 2009 Internet Security prior to 9.4.3202.9

  ArcaBit ArcaVir 2009 Antivirus Protection prior to 9.4.3201.9");
  script_tag(name:"insight", value:"This flaw is due to vulnerability in ps_drv.sys driver, which allows any users
  to open the device '\\Device\\ps_drv' and issue IOCTLs with a buffering mode of
  METHOD_NEITHER.");
  script_tag(name:"solution", value:"Apply the security updates accordingly.");
  script_tag(name:"summary", value:"This host is running ArcaVir AntiVirus Products and is prone to Privilege
  Escalation Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker pass kernel addresses as the
  arguments to the driver and overwrite an arbitrary address in the kernel space
  through a specially crafted IOCTL.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

arvaavVer = get_kb_item("ArcaVir/AntiVirus/Ver");
if(!arvaavVer)
  exit(0);

if(version_is_less(version:arvaavVer, test_version:"9.4.3201.9")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
