###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elasticsearch_logstash_detect.nasl 50069 2016-06-23 15:43:25 +0530 June$
#
# Elasticsearch Logstash Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808093");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2016-06-21 12:44:48 +0530 (Tue, 21 Jun 2016)");
  script_name("Elasticsearch Logstash Version Detection");

  script_tag(name:"summary", value:"Check for the version of Elasticsearch
  Logstash.

  This script sends an HTTP GET request and tries to get the version of
  Elasticsearch Logstash from the response.

  This plugin has been deprecated and merged into the NVT 'Elasticsearch and Logstash Detection'
  (OID: 1.3.6.1.4.1.25623.1.0.105031)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

# This had only detected Elasticsearch and assumed that "Logstash" is installed.
# However port 9200 is the Elasticsearch service and the version gathering method
# previously used just gathered the Elasticsearch version once a "logstash" index
# was available.
exit(66);
