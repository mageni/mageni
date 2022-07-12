###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cybozu_office_2017_04_Info_Disc_vuln.nasl 11210 2018-09-04 09:13:50Z mmartin $
#
# Cybozu Office CVE-2016-4871 Denial of Service Vulnerability
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

CPE = "cpe:/a:cybozu:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107151");
  script_version("$Revision: 11210 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-04 11:13:50 +0200 (Tue, 04 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-04-24 08:56:53 +0200 (Mon, 24 Apr 2017)");
  script_cve_id("CVE-2016-4871");

  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Cybozu Office CVE-2016-4871 Denial of Service Vulnerability");
  script_tag(name:"summary", value:"DEPRECATED since this check is already covered in
  'Cybozu Office CVE-2016-4871 Denial of Service Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.107150)

  Cybozu Office is prone to a denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation of the issue will cause excessive system
  resource consumption, resulting in a denial-of-service condition.");

  script_tag(name:"affected", value:"Cybozu Office 9.0.0 through 10.4.0 are vulnerable");
  script_tag(name:"solution", value:"Update to Cybozu Office 10.4.0.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97716");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_mandatory_keys("CybozuOffice/Installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("host_details.inc");
include("version_func.inc");


if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port)){
  exit(0);
}

if(version_in_range(version: Ver, test_version:"9.0.0", test_version2:"10.4.0"))
{
  report =  report_fixed_ver(installed_version:Ver, fixed_version:"10.5.0");
  security_message(port:Port, data:report);
  exit(0);
}
