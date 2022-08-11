###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_glassfish_hash_collision_dos_vuln.nasl 12047 2018-10-24 07:38:41Z cfischer $
#
# Oracle GlassFish Server Hash Collision Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:oracle:glassfish_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802409");
  script_version("$Revision: 12047 $");
  script_cve_id("CVE-2011-5035");
  script_bugtraq_id(51194);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 09:38:41 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-01-05 16:15:38 +0530 (Thu, 05 Jan 2012)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish Server Hash Collision Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/903934");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2011-003.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed");
  script_require_ports("Services/www", 8080);

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
service via a specially crafted form sent in a HTTP POST request.");

  script_tag(name:"affected", value:"Oracle GlassFish version 3.1.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error within a hash generation function when hashing
form posts and updating a hash table. This can be exploited to cause a hash collision resulting in high CPU
consumption via a specially crafted form sent in a HTTP POST request.");

  script_tag(name:"solution", value:"Apply the updates from the referenced advisory.");

  script_tag(name:"summary", value:"The host is running GlassFish Server and is prone to denial of service
vulnerability.");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version:"3.1.1")) {
  security_message(port:port);
  exit(0);
}

exit(99);
