###############################################################################
# OpenVAS Vulnerability Test
#
# Elasticsearch Kibana Improper Authentication Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811410");
  script_version("2020-04-02T11:36:28+0000");
  script_cve_id("CVE-2016-10364");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2017-07-03 20:27:52 +0530 (Mon, 03 Jul 2017)");
  script_name("Elasticsearch Kibana Improper Authentication Vulnerability");

  script_tag(name:"summary", value:"This host is running Elasticsearch Kibana
  and is prone to improper authentication vulnerability.

  This NVT has been split into two NVTs with the OIDs 1.3.6.1.4.1.25623.1.0.108259 and
  1.3.6.1.4.1.25623.1.0.108260");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper authentication to
  requests to advanced settings and the short URL service.");

  script_tag(name:"impact", value:"Successful exploitation will lead an
  authenticated user to make requests to advanced settings and the short URL
  services regardless of their own permissions.");

  script_tag(name:"affected", value:"Elasticsearch Kibana version 5.0.0 and 5.0.1");

  script_tag(name:"solution", value:"Upgrade to Elasticsearch Kibana version
  5.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
