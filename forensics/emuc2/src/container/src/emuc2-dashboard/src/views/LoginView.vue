<template>
  <v-container class="fill-height">
    <v-responsive
      class="align-center fill-height mx-auto"
      max-width="900"
    >
      <div>
          <form @submit.prevent="submit">
            <v-text-field
            v-model="username.value.value"
            :error-messages="username.errorMessage.value"
            label="Username"
            ></v-text-field>

            <v-text-field
            v-model="password.value.value"
            :error-messages="password.errorMessage.value"
            label="Password"
            :append-inner-icon="visible ? 'mdi-eye' : 'mdi-eye-off'"
            :type="visible ? 'text' : 'password'"
            @click:append-inner="visible = !visible"
            ></v-text-field>

            <v-btn
            class="me-4"
            type="submit"
            >
            submit
            </v-btn>
            <div v-if="apiError" class="alert alert-danger mt-3 mb-0">{{apiError}}</div>
        </form>
      </div>
    </v-responsive>
  </v-container>
</template>

<script setup>
  import { ref } from 'vue'
  import { useField, useForm } from 'vee-validate'
  import { useAuthStore } from '@/stores';

  const visible = ref(false);
  const apiError = ref(null);

  const { handleSubmit, handleReset } = useForm({
    validationSchema: {
      username (value) {
        return true
      },
      password (value) {
        return true
      },
    },
  })
  const username = useField('username')
  const password = useField('password')

  const submit = handleSubmit(values => {
    const authStore = useAuthStore();
    return authStore.login(values.username, values.password)
                .catch(error => apiError.value = error)
  })
</script>