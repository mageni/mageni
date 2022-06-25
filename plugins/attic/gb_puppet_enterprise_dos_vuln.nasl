###############################################################################
# OpenVAS Vulnerability Test
#
# Puppet Enterprise 2017 < 2017.2.2 Denial of Service Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113101");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2018-02-02 11:40:38 +0100 (Fri, 02 Feb 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-2296");

  script_name("Puppet Enterprise 2017 < 2017.2.2 Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"Puppet Enterprise before 2017.2.2 is prone to a Denial of Service Vulnerability.

  This NVT has duplicated the existing NVT 'Puppet Enterprise 2017 < 2017.2.2 DoS Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.106930).");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In the affected versions, using specially formatted strings with certain formatting characters as Classifier node group names or RBAC role display names causes errors, effectively causing a DoS to the service.");

  script_tag(name:"affected", value:"Puppet Enterprise from 2017.1.0 through 2017.2.1");

  script_tag(name:"solution", value:"Update to 2017.2.2");

  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2017-2296");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
