###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quickheal_dos_May_17.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# QuickHeal CVE-2015-8285 Denial of Service Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:quickheal:antivirus_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107160");
  script_version("$Revision: 11982 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-02 10:28:58 +0200 (Tue, 02 May 2017)");
  script_cve_id("CVE-2015-8285");
  script_bugtraq_id(97996);

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"registry");
  script_name("QuickHeal CVE-2015-8285 Denial of Service Vulnerability");
  script_tag(name:"summary", value:"QuickHeal is prone to a denial-of-service vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists in the driver webssx.sys.");
  script_tag(name:"impact", value:"An attacker can exploit this issue to cause denial-of-service condition.");
  script_tag(name:"affected", value:"QuickHeal 16.00 is vulnerable");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97996");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("General");

  script_dependencies("gb_quick_heal_av_detect.nasl");
  script_mandatory_keys("QuickHeal/Antivirus6432/Pro/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");


if(!Ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version: Ver, test_version:"16.00"))
{
  report =  report_fixed_ver(installed_version:Ver, fixed_version:"See information supplied by the vendor");
  security_message(data:report);
  exit( 0 );
}

exit ( 99 );
