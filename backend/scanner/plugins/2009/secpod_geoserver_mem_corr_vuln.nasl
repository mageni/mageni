###############################################################################
# OpenVAS Vulnerability Test
#
# GeoServer Memory Corruption Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900946");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-7227");
  script_name("GeoServer Memory Corruption Vulnerability");
  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_geoserver_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("GeoServer/installed");

  script_tag(name:"impact", value:"Successful attacks may lead to failure to report service exception if the code
  encoding the output calls flush() before having written the full contents to the output.");

  script_tag(name:"affected", value:"GeoServer version before 1.6.1 and 1.7.0-beta1.");

  script_tag(name:"insight", value:"An error exists when PartialBufferOutputStream2 flushes the buffer contents even
  when it is handling an 'in memory buffer', which prevents the reporting of a
  service exception, with unknown impact and attack vectors.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to version 1.6.1 or 1.7.0-beta1 or later.");

  script_tag(name:"summary", value:"This host is installed with GeoServer and is prone to a Memory
  Corruption vulnerability.");

  script_xref(name:"URL", value:"http://jira.codehaus.org/browse/GEOS-1747");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

geoPort = get_http_port(default:8080);

geoVer = get_kb_item("www/" + geoPort + "/GeoServer");
geoVer = eregmatch(pattern:"^(.+) under (/.*)$", string:geoVer);

if(geoVer[1] != NULL)
{
  if(version_is_less(version:geoVer[1], test_version:"1.6.1") ||
     version_in_range(version:geoVer[1], test_version:"1.7",
                                        test_version2:"1.7.0.beta")){
    security_message(port:geoPort, data:"The target host was found to be vulnerable.");
    exit(0);
  }
}

exit(99);
