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

package org.linkedin.glu.groovy.utils.concurrent

import org.linkedin.glu.groovy.utils.GluGroovyLangUtils

/**
 * @author ypujante@linkedin.com */

class FutureExecutionImpl<T> extends FutureTaskExecution<T> implements Comparable<FutureExecutionImpl>
{
  /**
   * id in the queue */
  int queueId

  /**
   * The callback to call on cancel
   */
  Closure onCancelPreCallback

  /**
   * The callback to call on cancel
   */
  Closure onCancelPostCallback

  FutureExecutionImpl()
  {
    super()
  }

  boolean cancel(boolean mayInterruptIfRunning)
  {
    def res = false

    if(onCancelPreCallback)
      res = GluGroovyLangUtils.noExceptionWithValueOnException(false) { onCancelPreCallback(this) }

    if(!res)
      res = super.cancel(mayInterruptIfRunning)

    if(onCancelPostCallback)
      GluGroovyLangUtils.noException { onCancelPostCallback(res, this) }

    return res
  }

  int compareTo(FutureExecutionImpl o)
  {
    int diff = futureExecutionTime.compareTo(o.futureExecutionTime)
    if(diff == 0)
    {
      diff = queueId - o.queueId
    }
    return diff
  }

  def String toString()
  {
    StringBuilder sb = new StringBuilder("class=${this.getClass().simpleName}")

    sb << ", id=${id}"
    sb << ", queueId=${queueId}"
    if(futureExecutionTime)
      sb << ", futureExecutionTime=${new Date(futureExecutionTime)}(${futureExecutionTime})"
    if(startTime)
      sb << ", startTime=${new Date(startTime)}"
    if(completionTime)
      sb << ", completionTime=${new Date(completionTime)}"

    return sb.toString();
  }
}