###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_registry_ok.nasl 11532 2018-09-21 19:07:30Z cfischer $
#
# Windows Registry Check: OK
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.105989");
  script_version("$Revision: 11532 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 21:07:30 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-05-22 12:45:19 +0700 (Fri, 22 May 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Windows Registry Check: OK");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("Policy/policy_registry.nasl");
  script_mandatory_keys("policy/registry/started");

  script_tag(name:"summary", value:"List registry entries which pass the registry
  policy check.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

passes = get_kb_list( "policy/registry/ok_list" );

if( passes ) {

  # Sort to not report changes on delta reports if just the order is different
  passes = sort( passes );

  report  = 'The following registry entries are correct:\n\n';
  report += 'Registry entry | Present | Value checked | Value set\n';

  foreach pass( passes ) {
    report += pass + '\n';
  }
  log_message( port:0, data:report );
}

exit( 0 );
