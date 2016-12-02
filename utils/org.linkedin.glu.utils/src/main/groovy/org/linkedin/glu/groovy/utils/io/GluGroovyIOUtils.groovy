/*
 * Copyright (c) 2012-2013 Yan Pujante
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

package org.linkedin.glu.groovy.utils.io

import org.codehaus.groovy.control.CompilationUnit
import org.codehaus.groovy.control.CompilerConfiguration
import org.linkedin.glu.groovy.utils.json.GluGroovyJsonUtils
import org.linkedin.glu.utils.io.MultiplexedInputStream
import org.linkedin.glu.utils.io.NullOutputStream
import org.linkedin.groovy.util.ant.AntUtils
import org.linkedin.groovy.util.io.GroovyIOUtils
import org.linkedin.util.io.resource.Resource
import org.linkedin.groovy.util.io.fs.FileSystem

import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKeyFactory
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.nio.file.Path
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.KeySpec

/**
 * @author yan@pongasoft.com */
public class GluGroovyIOUtils extends GroovyIOUtils
{
  static InputStream decryptStream(String password, InputStream inputStream)
  {
    new CipherInputStream(inputStream, computeCipher(password, Cipher.DECRYPT_MODE))
  }

  static def withStreamToDecrypt(String password, InputStream inputStream, Closure closure)
  {
    decryptStream(password, inputStream).withStream { closure(it) }
  }

  static OutputStream encryptStream(String password, OutputStream outputStream)
  {
    new CipherOutputStream(outputStream, computeCipher(password, Cipher.ENCRYPT_MODE))
  }

  static def withStreamToEncrypt(String password, OutputStream outputStream, Closure closure)
  {
    encryptStream(password, outputStream).withStream { closure(it) }
  }

  /**
   * Compiles a set of sources (using an optional classpath) and jar it into the destination jar
   *
   * @param fs where the jar file is relative to (as well as temp space)
   * @param sources list of sources (use {@link #toFile(Object)} to convert into a file)
   * @param jar destination jar file
   * @param classpath optional classpath (list/set of other jar files) (use
   *                  {@link #toFile(Object)} to convert into a file)
   * @return
   */
  static Resource compileAndJar(FileSystem fs, def sources, def jar, def classpath = null)
  {
    def cc = new CompilerConfiguration()
    fs.withTempFile { Resource targetDirectory ->
      cc.targetDirectory = fs.mkdirs(targetDirectory).file
      if(classpath)
        cc.classpathList = classpath.collect { toFile(it).canonicalPath }
      CompilationUnit cu = new CompilationUnit(cc)
      sources.each {
        cu.addSource(toFile(it))
      }
      cu.compile()

      Resource jarFile = fs.toResource(jar)

      AntUtils.withBuilder { ant ->
        ant.jar(destfile: jarFile.file, basedir: cc.targetDirectory)
      }
      return jarFile
    }
  }


  private static Cipher computeCipher(String password, int mode)
  {
    // If we are encrypting, generate a secure random 128-bit initialization vector
    // Otherwise, use the IV from the cipher
    //Cipher cipher = Cipher.getInstance("PKCS5Padding")
    /*if (mode == Cipher.ENCRYPT_MODE) {
        def seed = [16] as byte[]
        SecureRandom secureRNG = new SecureRandom(seed)
    }
    else if (mode == Cipher.DECRYPT_MODE) {
        def iv = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ] as byte[]//new byte[cipher.getBlockSize()]
    }
    else {
        //raise an error here
    }*/
    //secureRNG.nextBytes(iv)
    //IvParameterSpec ivspec = new IvParameterSpec(iv)
    //MessageDigest digest = MessageDigest.getInstance("SHA256")
    //SecretKeySpec key = new SecretKeySpec(digest.digest(password.getBytes("UTF-8")), "AES")
    //def salt = [256] as byte[]
    //SecureRandom secureRNG = new SecureRandom()
    //secureRNG.nextBytes(salt)
    //KeySpec spec = new PBEKeySpec(password.toCharArray())
    //SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
    //KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1, 256)
    //SecretKey tmp = keyFactory.generateSecret(spec)
    //SecretKeySpec key = new SecretKeySpec(tmp.getEncoded(), "AES")

    Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding")
    MessageDigest digest = MessageDigest.getInstance("SHA-256")
    SecretKeySpec key = new SecretKeySpec(digest.digest(password.getBytes("UTF-8")), "AES")
    // build the initialization vector.  This example is all zeros, but it
    // could be any value or generated using a random number generator.
    def iv = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ] as byte[]
    IvParameterSpec ivspec = new IvParameterSpec(iv)
    cipher.init(mode, key, ivspec)
    return cipher
  }

  /**
   * Demultiplexes the exec stream as generated by
   * {@link org.linkedin.glu.groovy.utils.shell.Shell#exec(Map)} when <code>args.res</code> is
   * <code>stream</code>. The following is equivalent:
   *
   * OutputStream myStdout = ...
   * OutputStream myStderr = ...
   *
   * exec(command: xxx, stdout: myStdout, stderr: myStderr, res: exitValue)
   *
   * is 100% equivalent to:
   *
   * demultiplexExecStream(exec(command: xxx, res: stream), myStdout, myStderr)
   *
   * @param execStream the stream as generated by {@link org.linkedin.glu.groovy.utils.shell.Shell#exec(Map)}
   * @param stdout the stream to write the output (optional, can be <code>null</code>)
   * @param stderr the stream to write the error (optional, can be <code>null</code>)
   * @return the value returned by the executed sub-process
   */
  public static def demultiplexExecStream(InputStream execStream,
                                          OutputStream stdout,
                                          OutputStream stderr)
  {
    def exitValueStream = new ByteArrayOutputStream()
    def exitErrorStream = new ByteArrayOutputStream()

    def streams = [:]

    streams[StreamType.stdout.multiplexName] = stdout ?: NullOutputStream.INSTANCE
    streams[StreamType.stderr.multiplexName] = stderr ?: NullOutputStream.INSTANCE
    streams[StreamType.exitValue.multiplexName] = exitValueStream
    streams[StreamType.exitError.multiplexName] = exitErrorStream

    // we demultiplex the stream
    MultiplexedInputStream.demultiplex(execStream, streams)

    // it means we got an exception, we throw it back
    if(exitErrorStream.size() > 0)
    {
      throw GluGroovyJsonUtils.rebuildException(new String(exitErrorStream.toByteArray(), "UTF-8"))
    }
    else
    {
      if(exitValueStream.size() == 0)
        return null

      String exitValueAsString = new String(exitValueStream.toByteArray(), "UTF-8")
      try
      {
        return Integer.valueOf(exitValueAsString)
      }
      catch(NumberFormatException e)
      {
        // this should not really happen but just in case...
        return exitValueAsString
      }
    }
  }

  /**
   * @return the file extension of the resource or <code>null</code> if none
   */
  public static String getFileExtension(Resource resource)
  {
    doGetFileExtension(resource?.filename)
  }

  /**
   * @return the file extension of the file or <code>null</code> if none
   */
  public static String getFileExtension(File file)
  {
    doGetFileExtension(file?.name)
  }

  /**
   * @return the file extension of the path or <code>null</code> if none
   */
  public static String getFileExtension(Path path)
  {
    doGetFileExtension(path?.fileName?.toString())
  }

  /**
   * @return the file extension of the resource or <code>null</code> if none
   */
  private static String doGetFileExtension(String path)
  {
    if(path == null)
      return null

    int idx = path.lastIndexOf('.')

    // this accounts for no extension, a file starting with . (like .cshrc) or a file ending with .
    if(idx <= 0 || idx == path.size() -1)
      return null

    return path[idx+1..-1]

  }

}
