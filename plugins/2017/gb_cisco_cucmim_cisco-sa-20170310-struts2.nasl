###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_cucmim_cisco-sa-20170310-struts2.nasl 13999 2019-03-05 13:15:01Z cfischer $
#
# Cisco Unified Communications Manager IM and Presence Service Apache Struts2 Jakarta Multipart Parser File Upload Code Execution Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:cisco:unified_communications_manager_im_and_presence_service";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106646");
  script_cve_id("CVE-2017-5638");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13999 $");

  script_name("Cisco Unified Communications Manager IM and Presence Service Apache Struts2 Jakarta Multipart Parser File Upload Code Execution Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170310-struts2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Cisco Unified Communications Manager IM and Presence Service is prone to a
  vulnerability in Apache Struts2.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 14:15:01 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-03-14 09:51:18 +0700 (Tue, 14 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_cucmim_version.nasl");
  script_mandatory_keys("cisco/cucmim/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

version = str_replace( string:version, find:"-", replace:"." );

if (version =~ "^11\.0" || version =~ "^11\.5") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);