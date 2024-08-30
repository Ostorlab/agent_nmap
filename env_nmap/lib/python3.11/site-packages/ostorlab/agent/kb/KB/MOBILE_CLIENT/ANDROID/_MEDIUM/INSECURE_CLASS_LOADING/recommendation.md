To mitigate the risk of Android Class Loading Hijacking, developers should: 

- Avoid using dynamic class loading methods unless necessary. 
- Ensure that the loaded classes are from a trusted source.
- Ensure that the loaded classes are not writable by other application.

=== "Java"
	```java
	public final class DexClassLoaderCall {
	
	    private static final String TAG = DexClassLoaderCall.class.toString();
	
	    @Override
	    public String getDescription() {
	        return "Use of dex class load";
	    }
	
	    @Override
	    public void run() throws Exception {
	        Context context = getContext(); 
	        File apkFile = new File(context.getFilesDir(), "app.apk");
	        DexClassLoader classLoader1 = new DexClassLoader(
	                apkFile.getAbsolutePath(),
	                context.getCacheDir().getAbsolutePath(),
	                null,
	                context.getClassLoader());
	        classLoader1.loadClass("a.b.c");
	
	        DexClassLoader classLoader2 = new DexClassLoader(
	                context.getPackageCodePath(),
	                context.getCacheDir().getAbsolutePath(),
	                null,
	                context.getClassLoader());
	        classLoader2.loadClass("a.b.c");
	    }
	}
	
	```

