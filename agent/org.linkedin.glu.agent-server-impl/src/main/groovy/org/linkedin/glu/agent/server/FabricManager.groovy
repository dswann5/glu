/*
 * Copyright (c) 2010-2010 LinkedIn, Inc
 * Portions Copyright (c) 2011 Yan Pujante
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.linkedin.glu.agent.server

import org.apache.zookeeper.CreateMode
import org.apache.zookeeper.ZooDefs.Ids
import org.linkedin.groovy.util.concurrent.GroovyConcurrentUtils
import org.linkedin.zookeeper.client.IZKClient
import org.linkedin.zookeeper.tracker.NodeEventsListener
import org.linkedin.zookeeper.tracker.ZooKeeperTreeTracker
import org.linkedin.zookeeper.tracker.ZKStringDataReader
import org.linkedin.util.clock.Clock
import org.linkedin.util.clock.SystemClock
import org.apache.zookeeper.KeeperException

/**
 * Manages the fabric: read it from a file or get it from zookeeper.
 *
 * @author ypujante@linkedin.com */
class FabricManager
{
  public static final String MODULE = FabricManager.class.getName();
  public static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MODULE);

  Clock clock = SystemClock.INSTANCE

  private final IZKClient _zkClient
  private final String _agentPath
  private final String _newFabric
  private final String _previousFabric
  private final File _fabricFile

  private String _fabric

  FabricManager(IZKClient zkClient,
                String agentPath,
                String newFabric,
                String previousFabric,
                File fabricFile)
  {
    _zkClient = zkClient
    _agentPath = agentPath
    _newFabric = newFabric
    _previousFabric = previousFabric
    _fabricFile = fabricFile
  }

  String getFabric()
  {
    return getFabric(null)
  }

  String getFabric(timeout)
  {
    if(_fabric != null)
      return _fabric
    else
    {
      if(_newFabric)
      {
        _fabric = _newFabric
      }
      else
      {
        if(_zkClient)
        {
          _fabric = readFabricFromZooKeeper()

          if(!_fabric)
            _fabric = _previousFabric

          if(!_fabric)
            _fabric = getFabricFromZookeeper(timeout)
        }

        if(!_fabric && _fabricFile?.exists())
        {
          _fabric = _fabricFile.text.trim()
        }
      }

      if(_fabric && _zkClient)
        saveFabricToZooKeeper(_fabric)
    }

    return _fabric
  }

  void saveFabricToZooKeeper(String fabric)
  {
    String fabricPath = FabricTracker.computeFabricPath(_agentPath)

    if(log.isDebugEnabled())
      log.debug("saving fabric to ZooKeeper: ${fabricPath} -> ${fabric}")

    _zkClient.createOrSetWithParents(fabricPath,
                                     fabric,
                                     Ids.OPEN_ACL_UNSAFE,
                                     CreateMode.PERSISTENT)
  }

  private String readFabricFromZooKeeper()
  {
    if(log.isDebugEnabled())
      log.debug("reading fabric from ZooKeeper: ${_agentPath}")

    try
    {
      return _zkClient.getStringData(FabricTracker.computeFabricPath(_agentPath))
    }
    catch (KeeperException.NoNodeException e)
    {
      return null
    }
  }

  private String getFabricFromZookeeper(timeout)
  {
    // agent currently does not have an fabric... will wait until assigned one

    if(log.isDebugEnabled())
      log.debug("getting fabric from ZooKeeper: ${_agentPath}")

    if(!_zkClient.exists(_agentPath))
    {
      _zkClient.createWithParents(_agentPath,
                                  null,
                                  Ids.OPEN_ACL_UNSAFE,
                                  CreateMode.PERSISTENT)
    }

    return new FabricTracker(clock, _zkClient, _agentPath).waitForFabric(timeout)
  }
}

class FabricTracker implements NodeEventsListener
{
  public static final String MODULE = FabricTracker.class.getName();
  public static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MODULE);

  private Clock clock
  private final IZKClient _zkClient
  private final String _agentPath
  private final String _fabricPath

  private ZooKeeperTreeTracker _tracker

  private String _fabric

  public static String computeFabricPath(String agentPath)
  {
    return "${agentPath}/fabric".toString()
  }

  FabricTracker(Clock clock, IZKClient zkClient, String agentPath)
  {
    this.clock = clock
    _zkClient = zkClient
    _agentPath = agentPath
    _fabricPath = computeFabricPath(_agentPath)
  }

  public synchronized void onEvents(Collection events)
  {
    if(log.isDebugEnabled())
      log.debug("received events: ${events}")

    events.each { event ->
      if(event.path == _fabricPath)
      {
        _fabric = event.data

        if(log.isDebugEnabled())
          log.debug("assigned fabric from zookeeper:${_fabricPath} => ${_fabric}")
      }
    }

    if(_fabric != null)
      notifyAll()
  }

  synchronized String waitForFabric(timeout)
  {
    _tracker = new ZooKeeperTreeTracker(_zkClient, ZKStringDataReader.INSTANCE, _agentPath, 1)
    try
    {
      if(log.isDebugEnabled())
        log.debug("Starting ZooKeeper tracker and waiting for fabric")

      log.info "Waiting for fabric @ zookeeper:${_fabricPath}"

      _tracker.track(this)

      GroovyConcurrentUtils.awaitFor(clock, timeout, this) {
        _fabric != null
      }
    }
    finally
    {
      _tracker.destroy()
    }

    return _fabric
  }
}