package net.jalg.hawkj.ext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 */
public class InputStreamBuffer extends InputStream {
	protected InputStream inputStream;
	protected ByteArrayOutputStream buffer = new ByteArrayOutputStream();

	public InputStreamBuffer(InputStream inputStream) {
		this.inputStream = inputStream;
	}

	public byte[] getBuffer() {
		return buffer.toByteArray();
	}

	@Override
	public int read() throws IOException {
		int b = inputStream.read();
		if (b > -1)
			buffer.write((byte) b);
		return b;
	}

	@Override
	public int read(byte[] bytes) throws IOException {
		int nbytes = inputStream.read(bytes);
		if (nbytes > 0) {
			buffer.write(bytes, 0, nbytes);
		}
		return nbytes;
	}

	@Override
	public int read(byte[] bytes, int off, int len) throws IOException {
		int nbytes = inputStream.read(bytes, off, len);
		if (nbytes > 0) {
			buffer.write(bytes, off, nbytes);
		}
		return nbytes;
	}

	@Override
	public long skip(long l) throws IOException {
		return inputStream.skip(l);
	}

	@Override
	public int available() throws IOException {
		return inputStream.available();
	}

	@Override
	public void close() throws IOException {
		inputStream.close();
	}

	@Override
	public void mark(int i) {
		inputStream.mark(i);
	}

	@Override
	public void reset() throws IOException {
		throw new RuntimeException("Resetting stream not permitted");
	}

	@Override
	public boolean markSupported() {
		return inputStream.markSupported();
	}
}
